defmodule Portal.Application do
  use Application

  require Logger

  @impl true
  def start(_type, _args) do
    configure_logger()
    verify_geolix_databases()

    # Attach Oban Sentry reporter
    Portal.Telemetry.Reporter.Oban.attach()

    # OpenTelemetry setup
    :ok = OpentelemetryLoggerMetadata.setup()
    :ok = OpentelemetryEcto.setup([:portal, :repo])
    :ok = OpentelemetryEcto.setup([:portal, :repo, :replica])
    :ok = OpentelemetryEcto.setup([:portal, :repo, :web])
    :ok = OpentelemetryEcto.setup([:portal, :repo, :api])
    :ok = OpentelemetryEcto.setup([:portal, :repo, :replica, :web])
    :ok = OpentelemetryEcto.setup([:portal, :repo, :replica, :api])
    :ok = OpentelemetryBandit.setup()
    :ok = OpentelemetryPhoenix.setup(adapter: :bandit)
    :ok = OpentelemetryOban.setup()

    Supervisor.start_link(children(), strategy: :one_for_one, name: __MODULE__.Supervisor)
  end

  @impl true
  def stop(_state) do
    # Remove the Sentry logger handler before Sentry.Supervisor terminates
    # to avoid noproc errors during shutdown
    _ = :logger.remove_handler(:sentry)
    :ok
  end

  defp children do
    base_children = [
      # Core services
      Portal.Repo,
      Portal.Repo.Replica,
      # Isolated connection pools (web/api)
      Portal.Repo.Web,
      Portal.Repo.Api,
      Portal.Repo.Replica.Web,
      Portal.Repo.Replica.Api,
      # Default pg scope for distributed process discovery (used by replication)
      %{id: :pg, start: {:pg, :start_link, []}},
      # Named pg scope for Portal.PG, isolated so a crash here does not affect replication
      %{id: Portal.PG, start: {:pg, :start_link, [Portal.PG]}},
      Portal.PubSub,

      # Application services
      Portal.Presence,
      Portal.Mailer.RateLimiter,
      Portal.ComponentVersions
    ]

    endpoint_children = [
      # Give Phoenix socket drain enough time to gracefully close channel topics
      # before transports are force-terminated.
      {PortalWeb.Endpoint, shutdown: 40_000},
      {PortalAPI.Endpoint, shutdown: 40_000},
      {PortalOps.Endpoint, shutdown: 40_000}
    ]

    # Child order is chosen to make reverse-order shutdown graceful:
    # 1) Portal.Cluster sends goodbye while DB/PubSub are healthy.
    # 2) Replication managers disconnect while BEAM is still fully alive.
    # 3) Endpoints drain and terminate channels while Presence/PubSub/Repo are alive.
    # 4) Portal{API,Web}.RateLimit stops after endpoint traffic has ceased.
    base_children ++
      client_session_queue() ++
      gateway_session_queue() ++
      policy_authorization_queue() ++
      rate_limit() ++
      telemetry() ++ oban() ++ endpoint_children ++ replication() ++ [Portal.Cluster]
  end

  defp configure_logger do
    # Attach Oban to the logger
    Oban.Telemetry.attach_default_logger(encode: false, level: log_level())

    # Configure Logger severity at runtime
    :ok = LoggerJSON.configure_log_level_from_env!("LOG_LEVEL")

    config = Application.get_env(:logger_json, :config)

    if not is_nil(config) do
      formatter = LoggerJSON.Formatters.Basic.new(config)
      :logger.update_handler_config(:default, :formatter, formatter)
    end

    # Configure Sentry to capture Logger messages
    :logger.add_handler(:sentry, Sentry.LoggerHandler, %{
      config: %{
        level: :warning,
        metadata: :all,
        capture_log_messages: true
      }
    })
  end

  defp log_level do
    case System.get_env("LOG_LEVEL") do
      "error" -> :error
      "warn" -> :warn
      "debug" -> :debug
      _ -> :info
    end
  end

  defp client_session_queue do
    queue_child(:client_session_queue,
      name: :client_session_queue,
      schema: Portal.ClientSession,
      flush_interval: :timer.seconds(5),
      flush_threshold: 1_000,
      label: "client session",
      on_failed: fn attrs, _ -> Portal.PG.deliver(attrs.device_id, :disconnect) end,
      on_confirmed: &PortalAPI.Client.Channel.confirm_session_durability/1,
      fk_partitions: %{
        "client_sessions_account_id_fkey" => {:simple, :account_id, Portal.Account},
        "client_sessions_device_id_fkey" => {:composite, :device_id, Portal.Device},
        "client_sessions_client_token_id_fkey" =>
          {:composite, :client_token_id, Portal.ClientToken}
      }
    )
  end

  defp gateway_session_queue do
    queue_child(:gateway_session_queue,
      name: :gateway_session_queue,
      schema: Portal.GatewaySession,
      flush_interval: :timer.seconds(5),
      flush_threshold: 1_000,
      label: "gateway session",
      on_failed: fn attrs, _ -> Portal.PG.deliver(attrs.device_id, :disconnect) end,
      on_confirmed: &PortalAPI.Gateway.Channel.confirm_session_durability/1,
      fk_partitions: %{
        "gateway_sessions_account_id_fkey" => {:simple, :account_id, Portal.Account},
        "gateway_sessions_device_id_fkey" => {:composite, :device_id, Portal.Device},
        "gateway_sessions_gateway_token_id_fkey" =>
          {:composite, :gateway_token_id, Portal.GatewayToken}
      }
    )
  end

  defp policy_authorization_queue do
    queue_child(:policy_authorization_queue,
      name: :policy_authorization_queue,
      schema: Portal.PolicyAuthorization,
      flush_interval: :timer.seconds(1),
      flush_threshold: 10_000,
      label: "policy authorization",
      failed_log_level: :warning,
      on_failed: &PortalAPI.Client.Channel.revoke_receiver_access/2,
      on_confirmed: &PortalAPI.Client.Channel.confirm_authz_durability/1,
      fk_partitions: %{
        "policy_authorizations_account_id_fkey" => {:simple, :account_id, Portal.Account},
        "policy_authorizations_policy_id_fkey" => {:composite, :policy_id, Portal.Policy},
        "policy_authorizations_resource_id_fkey" =>
          {:composite, :resource_id, Portal.Resource},
        "policy_authorizations_token_id_fkey" =>
          {:composite, :token_id, Portal.ClientToken},
        "policy_authorizations_membership_id_fkey" =>
          {:composite_optional, :membership_id, Portal.Membership},
        "policy_authorizations_initiating_device_id_fkey" =>
          {:composite, :initiating_device_id, Portal.Device},
        "policy_authorizations_receiving_device_id_fkey" =>
          {:composite, :receiving_device_id, Portal.Device}
      }
    )
  end

  defp queue_child(config_key, opts) do
    config = Portal.Config.get_env(:portal, config_key, [])

    if Keyword.get(config, :enabled, true) do
      [{Portal.Queue, opts}]
    else
      []
    end
  end

  defp telemetry do
    config = Application.fetch_env!(:portal, Portal.Telemetry)

    if config[:enabled] do
      [Portal.Telemetry]
    else
      []
    end
  end

  defp oban do
    # Skip starting Oban when only the application boot is needed (e.g. CI
    # generating the OpenAPI spec without a Postgres service). Oban 2.22+
    # verifies migrations at supervisor start, which requires a live DB.
    if Portal.Config.env_var_to_config!(:oban_enabled) do
      [{Oban, Application.fetch_env!(:portal, Oban)}]
    else
      []
    end
  end

  defp replication do
    connection_modules = [
      Portal.Changes.ReplicationConnection,
      Portal.ChangeLogs.ReplicationConnection
    ]

    # Filter out disabled replication connections
    Enum.reduce(connection_modules, [], fn module, enabled ->
      config = Application.fetch_env!(:portal, module)

      if config[:enabled] do
        spec = %{
          id: module,
          start: {Portal.Replication.Manager, :start_link, [module, []]}
        }

        [spec | enabled]
      else
        enabled
      end
    end)
  end

  defp rate_limit do
    [PortalAPI.RateLimit, PortalWeb.RateLimit]
  end

  defp verify_geolix_databases do
    # Geolix loads databases asynchronously via handle_continue, so they may
    # not be ready by the time Portal.Application.start/2 runs. Wait for the
    # async load to finish before proceeding with supervision tree startup.
    for %{id: id, source: source} <- Portal.Config.get_env(:geolix, :databases, []) do
      await_geolix_database(id, source, _retries = 30)
    end
  end

  defp await_geolix_database(id, source, 0) do
    Logger.error("Geolix database #{inspect(id)} failed to load from #{source}")
  end

  defp await_geolix_database(id, source, retries) do
    case Geolix.metadata(where: id) do
      nil ->
        Process.sleep(1000)
        await_geolix_database(id, source, retries - 1)

      _metadata ->
        :ok
    end
  end
end
