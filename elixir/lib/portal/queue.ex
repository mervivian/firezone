defmodule Portal.Queue do
  @moduledoc """
  Per-node GenServer that serializes message dispatch through its own pid
  and batches `INSERT`s into the configured Ecto schema.

  ## Why a single pid?

  Erlang only guarantees signal ordering between a specific sender pid and
  receiver pid. When two messages about the same logical event must arrive
  in send order at a remote pid — e.g. `:allow_access` followed by an
  eventual `:reject_access` if the row fails to persist, or
  `:confirm_authz_durability` if it succeeds — they must originate from a single
  sender pid. The Queue is that pid. All three callbacks run inside the
  Queue process and therefore share a sender:

    * `:dispatch` (passed per call to `enqueue/3`) — invoked before
      buffering; used to send the original allow message.
    * `:on_failed` (configured at start_link) — invoked once per entry that
      fails to persist; used to send `:reject_access`.
    * `:on_confirmed` (configured at start_link) — invoked once per entry
      that successfully persisted; used to send `:confirm_authz_durability` so
      receivers can cancel their authz durability timers.

  ## Required options

    * `:name` — registered name for the GenServer
    * `:schema` — Ecto schema module to insert into
    * `:flush_interval` — interval in ms between automatic flushes
    * `:flush_threshold` — entry count that triggers a flush via
      `handle_continue` (out of the call path, but before any further
      message is processed by this Queue)

  ## Optional options

    * `:label` — short string used in log lines (defaults to `inspect(schema)`)
    * `:fk_partitions` — `%{constraint_name => {kind, key, schema}}` where
      `kind` is `:simple | :composite | :composite_optional`. On a foreign-key
      violation we look up the constraint and split the batch into entries that
      reference an existing parent row vs. those that don't, so that valid
      entries still get persisted while orphaned ones go to `on_failed`.
      `:simple` — parent has only `id`. `:composite` — parent has
      `(account_id, id)`. `:composite_optional` — like `:composite`, but the FK
      column may be `nil` (those entries are kept as valid).
    * `:on_failed` — `fn attrs, metadata -> any` invoked once per failed entry,
      from the Queue process. Defaults to a no-op.
    * `:on_confirmed` — `fn attrs -> any` invoked once per successfully
      persisted entry, from the Queue process. Defaults to a no-op.
    * `:failed_log_level` — log level for the "skipped N entries" message
      (defaults to `:info`).
    * `:callers` — pids to copy into `$callers` so the GenServer inherits
      sandbox ownership in tests.
  """

  use GenServer
  alias __MODULE__.Database
  require Logger

  @type fk_partition_kind :: :simple | :composite | :composite_optional
  @type fk_partition :: {fk_partition_kind(), atom(), module()}
  @type on_failed :: (map(), term() -> any())
  @type on_confirmed :: (map() -> any())
  @type dispatch :: (-> term())

  defmodule Config do
    @moduledoc false
    @enforce_keys [
      :schema,
      :flush_interval,
      :flush_threshold,
      :label,
      :fk_partitions,
      :on_failed,
      :on_confirmed,
      :failed_log_level
    ]
    defstruct @enforce_keys
  end

  def child_spec(opts) do
    %{
      id: Keyword.fetch!(opts, :name),
      start: {__MODULE__, :start_link, [opts]}
    }
  end

  def start_link(opts) do
    name = Keyword.fetch!(opts, :name)
    GenServer.start_link(__MODULE__, opts, name: name)
  end

  @doc """
  Enqueues `attrs` for batched insertion.

  ## Options

    * `:dispatch` — 0-arity function executed synchronously in the Queue
      process *before* the entry is buffered. Its return value becomes the
      reply to the caller, so callers can react to e.g. `{:error, :not_found}`
      from a PG delivery. Because it runs in the Queue process, any
      message it sends shares a sender pid with subsequent `on_failed` /
      `on_confirmed` dispatches — giving downstream receivers per-pid
      ordering guarantees.

      If the dispatch returns `{:error, _}`, the entry is **not** buffered.
      This avoids persisting (and later `on_failed`-revoking) state for a
      delivery that never reached the receiver.

    * `:metadata` — arbitrary term passed to the `on_failed` callback if
      this entry later fails to persist.

  Returns the dispatch result if `:dispatch` is provided, otherwise `:ok`.
  """
  @spec enqueue(GenServer.server(), map(), keyword()) :: term()
  def enqueue(server, attrs, opts \\ []) when is_map(attrs) and is_list(opts) do
    GenServer.call(server, {:enqueue, attrs, opts})
  end

  @spec flush(GenServer.server()) :: :ok
  def flush(server) do
    GenServer.call(server, :flush)
  end

  @impl true
  def init(opts) do
    # Trap exits so `terminate/2` runs on supervisor-driven shutdown — gives
    # us a best-effort window to flush whatever's buffered before the node
    # goes down. Note this does NOT catch callback exceptions on its own;
    # those are covered by the defensive try/rescue inside `do_flush`,
    # `run_dispatch`, and the per-entry on_failed wrapper.
    Process.flag(:trap_exit, true)

    callers = Keyword.get(opts, :callers, [])
    Process.put(:"$callers", callers)

    schema = Keyword.fetch!(opts, :schema)

    config = %Config{
      schema: schema,
      flush_interval: Keyword.fetch!(opts, :flush_interval),
      flush_threshold: Keyword.fetch!(opts, :flush_threshold),
      label: Keyword.get(opts, :label, inspect(schema)),
      fk_partitions: Keyword.get(opts, :fk_partitions, %{}),
      on_failed: Keyword.get(opts, :on_failed, fn _attrs, _metadata -> :ok end),
      on_confirmed: Keyword.get(opts, :on_confirmed, fn _attrs -> :ok end),
      failed_log_level: Keyword.get(opts, :failed_log_level, :info)
    }

    schedule_flush(config.flush_interval)
    {:ok, %{config: config, buffer: [], count: 0}}
  end

  @impl true
  def handle_call({:enqueue, attrs, opts}, _from, state) do
    case run_dispatch(Keyword.get(opts, :dispatch)) do
      {:error, _} = error ->
        {:reply, error, state}

      reply ->
        metadata = Keyword.get(opts, :metadata)

        state = %{
          state
          | buffer: [{attrs, metadata} | state.buffer],
            count: state.count + 1
        }

        if state.count >= state.config.flush_threshold do
          {:reply, reply, state, {:continue, :flush}}
        else
          {:reply, reply, state}
        end
    end
  end

  @impl true
  def handle_call(:flush, _from, state) do
    {:reply, :ok, do_flush(state)}
  end

  @impl true
  def handle_continue(:flush, state) do
    {:noreply, do_flush(state)}
  end

  @impl true
  def handle_info(:flush, state) do
    schedule_flush(state.config.flush_interval)
    {:noreply, do_flush(state)}
  end

  @impl true
  def terminate(_reason, %{buffer: buffer, config: config} = state) do
    # Best-effort cleanup window. Two important caveats:
    #
    #   1. This only runs for supervisor-driven shutdown (and similar exit
    #      paths) once `trap_exit` is set. Hard crashes / SIGKILL bypass it,
    #      but the receiver-side authz durability timer (see channel handlers'
    #      `maybe_arm_authz_durability_timer`) covers those — every cached authz
    #      gets a 15s timer that fires `reject_access` if no confirm or
    #      explicit reject arrives.
    #   2. Endpoint children stop BEFORE queue children during graceful
    #      shutdown (see `Portal.Application.children/0`'s ordering rules),
    #      so by the time we get here the gateway/client channels on this
    #      node may already be gone. PG.deliver to a missing key is a silent
    #      no-op — that's fine, the gateway will re-hydrate its cache from
    #      DB on its next reconnect and any remote receivers' authz durability
    #      timers will fire if needed.
    #
    # So this terminate path is primarily useful for the case where the
    # queue itself dies but the receiver channels stay alive (e.g.
    # supervisor restart of the queue under load) — saves a 15s revoke
    # latency in that narrow case.
    if buffer != [] do
      Logger.warning(
        "Queue #{config.label} terminating with #{length(buffer)} buffered entries; " <>
          "attempting best-effort flush"
      )
    end

    try do
      _ = do_flush(state)
    rescue
      error ->
        Logger.error(
          "Queue #{config.label} terminate flush crashed: " <> Exception.message(error)
        )

        dispatch_failed(buffer, config)
    catch
      kind, reason ->
        Logger.error(
          "Queue #{config.label} terminate flush threw #{kind}: " <> inspect(reason)
        )

        dispatch_failed(buffer, config)
    end

    :ok
  end

  defp run_dispatch(nil), do: :ok

  defp run_dispatch(fun) when is_function(fun, 0) do
    fun.()
  rescue
    error ->
      Logger.error("Queue dispatch crashed: " <> Exception.message(error))
      {:error, :dispatch_crashed}
  catch
    kind, reason ->
      Logger.error("Queue dispatch threw #{kind}: " <> inspect(reason))
      {:error, :dispatch_crashed}
  end

  defp do_flush(%{buffer: [], count: 0} = state), do: state

  defp do_flush(%{buffer: buffer, config: config} = state) do
    now = DateTime.utc_now()

    entries =
      Enum.map(buffer, fn {attrs, metadata} ->
        {Map.put(attrs, :inserted_at, now), metadata}
      end)

    {inserted, failed} = Database.insert_all(entries, config)

    dispatch_failed(failed, config)
    dispatch_confirmed(entries, failed, config)

    if failed != [] do
      Logger.log(
        config.failed_log_level,
        "Skipped #{length(failed)} #{config.label} entries during flush due to missing references"
      )
    end

    Logger.info("Flushed #{inserted} #{config.label} entries")

    %{state | buffer: [], count: 0}
  end

  # Invokes on_failed for each entry independently so a single callback raise
  # cannot kill the queue process and lose the remaining buffered entries.
  defp dispatch_failed(entries, config) do
    for {attrs, metadata} <- entries do
      try do
        config.on_failed.(attrs, metadata)
      rescue
        error ->
          Logger.error(
            "Queue #{config.label} on_failed crashed for entry #{inspect(attrs[:id])}: " <>
              Exception.message(error)
          )
      catch
        kind, reason ->
          Logger.error(
            "Queue #{config.label} on_failed threw #{kind} for entry #{inspect(attrs[:id])}: " <>
              inspect(reason)
          )
      end
    end

    :ok
  end

  # Invokes on_confirmed for each entry that successfully persisted. Used by
  # receivers as the "cancel authz durability timer" signal: if no confirm arrives
  # for an entry the receiver previously got an allow for, the receiver's
  # local timer eventually fires and revokes the entry — fail-closed against
  # queue crashes / node death / netsplits between the queue's node and the
  # receiver's. Same per-entry try/rescue as on_failed.
  defp dispatch_confirmed(entries, failed, config) do
    failed_ids = MapSet.new(failed, fn {attrs, _} -> attrs[:id] end)

    for {attrs, _metadata} <- entries, not MapSet.member?(failed_ids, attrs[:id]) do
      try do
        config.on_confirmed.(attrs)
      rescue
        error ->
          Logger.error(
            "Queue #{config.label} on_confirmed crashed for entry #{inspect(attrs[:id])}: " <>
              Exception.message(error)
          )
      catch
        kind, reason ->
          Logger.error(
            "Queue #{config.label} on_confirmed threw #{kind} for entry #{inspect(attrs[:id])}: " <>
              inspect(reason)
          )
      end
    end

    :ok
  end

  defp schedule_flush(interval) do
    Process.send_after(self(), :flush, interval)
  end

  defmodule Database do
    @moduledoc false
    alias Portal.Safe
    import Ecto.Query
    require Logger

    def insert_all([], _config), do: {0, []}
    def insert_all(entries, config), do: do_insert_all(entries, [], 0, config)

    defp do_insert_all([], failed, inserted, _config), do: {inserted, failed}

    defp do_insert_all(entries, failed, inserted_acc, config) do
      attrs_list = Enum.map(entries, fn {attrs, _meta} -> attrs end)

      {inserted, _} =
        Safe.unscoped()
        |> Safe.insert_all(config.schema, attrs_list)

      {inserted_acc + inserted, failed}
    rescue
      error in [Postgrex.Error] ->
        case error.postgres do
          %{code: :foreign_key_violation, constraint: constraint} ->
            {valid, invalid} = partition_for_constraint(entries, constraint, config)
            do_insert_all(valid, failed ++ invalid, inserted_acc, config)

          _ ->
            # Route the batch through on_failed rather than crashing. For
            # policy_authorization this delivers reject_access to the
            # receiver; for sessions it disconnects the device. Crashing
            # here would lose state.buffer; the receiver's authz durability
            # timer would eventually catch the orphan, but on_failed is
            # the immediate path.
            Logger.error(
              "Queue #{config.label} flush failed (#{length(entries)} entries): " <>
                Exception.message(error)
            )

            {inserted_acc, failed ++ entries}
        end

      # Any other exception type (DBConnection.ConnectionError, Postgrex.QueryError,
      # an Ecto error from the partition lookup, etc.) — same treatment: route
      # the batch through on_failed instead of letting the queue process crash.
      # The receiver's authz durability timer is the last line of defense; on_failed
      # firing reject_access immediately is the preferred signal.
      error ->
        Logger.error(
          "Queue #{config.label} flush crashed (#{length(entries)} entries): " <>
            Exception.message(error)
        )

        {inserted_acc, failed ++ entries}
    catch
      kind, reason ->
        Logger.error(
          "Queue #{config.label} flush threw #{kind} (#{length(entries)} entries): " <>
            inspect(reason)
        )

        {inserted_acc, failed ++ entries}
    end

    defp partition_for_constraint(entries, constraint, config) do
      case Map.get(config.fk_partitions, constraint) do
        nil ->
          {[], entries}

        {:simple, key, schema} ->
          partition_by_simple(entries, key, schema)

        {:composite, key, schema} ->
          partition_by_composite(entries, key, schema)

        {:composite_optional, key, schema} ->
          {nil_entries, non_nil_entries} =
            Enum.split_with(entries, fn {attrs, _} -> is_nil(attrs[key]) end)

          {valid, invalid} = partition_by_composite(non_nil_entries, key, schema)
          {nil_entries ++ valid, invalid}
      end
    end

    defp partition_by_simple(entries, key, schema) do
      ids = entries |> Enum.map(fn {attrs, _} -> attrs[key] end) |> Enum.uniq()

      existing_ids =
        from(t in schema, where: t.id in ^ids, select: t.id)
        |> Safe.unscoped()
        |> Safe.all()
        |> MapSet.new()

      Enum.split_with(entries, fn {attrs, _} ->
        MapSet.member?(existing_ids, attrs[key])
      end)
    end

    defp partition_by_composite(entries, key, schema) do
      # Group lookups by account_id so the WHERE clause is `account_id = ? AND
      # id IN (^ids)` per account rather than a flat OR chain of (account_id,
      # id) pairs. The latter scales as O(batch_size) bind params (problematic
      # at the 10k-entry threshold); this scales as O(#accounts).
      ids_by_account =
        entries
        |> Enum.map(fn {attrs, _} -> {attrs[:account_id], attrs[key]} end)
        |> Enum.uniq()
        |> Enum.group_by(fn {account_id, _} -> account_id end, fn {_, id} -> id end)

      conditions =
        Enum.reduce(ids_by_account, dynamic(false), fn {account_id, ids}, acc ->
          dynamic([t], ^acc or (t.account_id == ^account_id and t.id in ^ids))
        end)

      existing_pairs =
        from(t in schema, where: ^conditions, select: {t.account_id, t.id})
        |> Safe.unscoped()
        |> Safe.all()
        |> MapSet.new()

      Enum.split_with(entries, fn {attrs, _} ->
        MapSet.member?(existing_pairs, {attrs[:account_id], attrs[key]})
      end)
    end
  end
end
