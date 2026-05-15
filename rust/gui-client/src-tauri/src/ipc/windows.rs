use super::{NotFound, SocketId};
use anyhow::{Context as _, Result, bail, ensure};
use sha2::{Digest, Sha256};
use std::{
    ffi::c_void, io::ErrorKind, os::windows::io::AsRawHandle, sync::OnceLock, time::Duration,
};
use tokio::net::windows::named_pipe;
use windows::Win32::{
    Foundation::{HANDLE, HLOCAL, LocalFree},
    Security::{
        Authorization::{GetSecurityInfo, SE_KERNEL_OBJECT},
        IsWellKnownSid, OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID,
        SECURITY_ATTRIBUTES, WinLocalSystemSid,
    },
    System::Pipes::{GetNamedPipeClientProcessId, GetNamedPipeServerProcessId},
};
use windows_security::pipe_dacl::{FileRights, PipeDacl, Trustee};

pub struct Server {
    pipe_path: String,
    socket_id: SocketId,
}

/// Alias for the client's half of a platform-specific IPC stream
pub type ClientStream = named_pipe::NamedPipeClient;

/// Alias for the server's half of a platform-specific IPC stream
pub(crate) type ServerStream = named_pipe::NamedPipeServer;

/// Connect to an IPC socket.
///
/// This is async on Linux
#[expect(clippy::unused_async)]
#[expect(clippy::wildcard_enum_match_arm)]
pub(crate) async fn connect_to_socket(id: SocketId) -> Result<ClientStream> {
    let path = ipc_path(id);
    let stream = named_pipe::ClientOptions::new()
        .open(&path)
        .map_err(|error| match error.kind() {
            ErrorKind::NotFound => anyhow::Error::new(NotFound(path)),
            _ => anyhow::Error::new(error),
        })
        .context("Couldn't connect to named pipe")?;
    let handle = HANDLE(stream.as_raw_handle());

    // Skip the owner check in debug builds so the `gui-smoke-test`, which
    // launches the Tunnel binary as a subprocess of the test runner (not as a
    // Windows service running under `LocalSystem`), can drive a real GUI
    // ↔ Tunnel handshake. Production builds are always release-mode (the
    // `gui-smoke-test` workflow explicitly skips release mode), so the check
    // is enforced there.
    if !cfg!(debug_assertions) && matches!(id, SocketId::Tunnel) {
        ensure_pipe_owner_is_local_system(handle)
            .context("Refusing to talk to non-LocalSystem Tunnel pipe server")?;
    }

    let mut server_pid: u32 = 0;
    // SAFETY: Windows doesn't store this pointer or handle, and we just got the handle
    // from Tokio, so it should be valid.
    unsafe { GetNamedPipeServerProcessId(handle, &mut server_pid) }
        .context("Couldn't get PID of named pipe server")?;

    tracing::debug!(?server_pid, "Made IPC connection");
    Ok(stream)
}

/// Verifies that the connected named pipe was created by `LocalSystem`, the
/// account the Tunnel service runs as.
///
/// `first_pipe_instance(true)` ensures nobody else can create another instance
/// of our pipe *while the legit server is bound*, but during the brief window
/// between teardown and re-bind (or before the service starts at all on a
/// just-booted machine) a local user-mode process can race to be the *first*
/// creator of the pipe name. The legit service then fails closed via
/// `ERROR_ACCESS_DENIED`, leaving the squatter as the only server. This check
/// catches that case before the GUI sends anything sensitive over the wire.
///
/// We inspect the *owner* of the kernel pipe object (set at creation time)
/// rather than the server's current process token. The latter is racy if the
/// server process exits and its PID is recycled between
/// `GetNamedPipeServerProcessId` and `OpenProcess`.
fn ensure_pipe_owner_is_local_system(handle: HANDLE) -> Result<()> {
    let mut owner_sid = PSID::default();
    let mut sd = PSECURITY_DESCRIPTOR::default();

    // SAFETY: All pointers below are out-pointers to stack locals. On success
    // the kernel allocates `sd` (which we release via `LocalFree`) and points
    // `owner_sid` into that allocation.
    let err = unsafe {
        GetSecurityInfo(
            handle,
            SE_KERNEL_OBJECT,
            OWNER_SECURITY_INFORMATION,
            Some(&mut owner_sid),
            None,
            None,
            None,
            Some(&mut sd),
        )
    };
    if err.0 != 0 {
        return Err(std::io::Error::from_raw_os_error(err.0 as i32))
            .context("GetSecurityInfo on pipe handle failed");
    }

    // SAFETY: `owner_sid` is a non-NULL pointer into `sd`'s buffer (still
    // alive for this call) and `IsWellKnownSid` does not retain it.
    let is_local_system = unsafe { IsWellKnownSid(owner_sid, WinLocalSystemSid) }.as_bool();

    // SAFETY: `sd` was allocated by `GetSecurityInfo` and must be released
    // with `LocalFree`. After this call no pointer derived from it is used.
    unsafe {
        let _ = LocalFree(Some(HLOCAL(sd.0)));
    }

    ensure!(
        is_local_system,
        "Tunnel pipe owner is not LocalSystem; possible pipe-squatting attack"
    );
    Ok(())
}

impl Server {
    /// Platform-specific setup
    #[expect(clippy::unnecessary_wraps, reason = "Linux impl is fallible")]
    pub(crate) fn new(id: SocketId) -> Result<Self> {
        let pipe_path = ipc_path(id);
        Ok(Self {
            pipe_path,
            socket_id: id,
        })
    }

    // `&mut self` needed to match the Linux signature
    pub(crate) async fn next_client(&mut self) -> Result<ServerStream> {
        // Fixes #5143. In the Tunnel service, if we close the pipe and immediately re-open
        // it, Tokio may not get a chance to clean up the pipe. Yielding seems to fix
        // this in tests, but `yield_now` doesn't make any such guarantees, so
        // we also do a loop.
        tokio::task::yield_now().await;

        let server = self
            .bind_to_pipe()
            .await
            .context("Couldn't bind to named pipe")?;
        // Note that Tokio has no `poll_connect`
        server
            .connect()
            .await
            .context("Couldn't accept IPC connection from GUI")?;
        let handle = HANDLE(server.as_raw_handle());
        let mut client_pid: u32 = 0;
        // SAFETY: Windows doesn't store this pointer or handle, and we just got the handle
        // from Tokio, so it should be valid.
        unsafe { GetNamedPipeClientProcessId(handle, &mut client_pid) }
            .context("Couldn't get PID of named pipe client")?;
        tracing::debug!(?client_pid, "Accepted IPC connection");
        Ok(server)
    }

    async fn bind_to_pipe(&self) -> Result<ServerStream> {
        // Defense-in-depth around #5143: when an IPC handler panics or otherwise
        // tears down the pipe and we immediately re-bind, Windows can briefly
        // return `AccessDenied` because the previous instance hasn't been fully
        // released yet. Polling on a short cadence is plenty — this typically
        // clears in tens of milliseconds. The previous 1s sleep was long enough
        // to make the `panic_inside_handler_doesnt_interrupt_service` unit test
        // race the test-side reconnect window on the `windows-2025` CI runner.
        const NUM_ITERS: usize = 100;
        const RETRY_INTERVAL: Duration = Duration::from_millis(100);
        for i in 0..NUM_ITERS {
            match create_pipe_server(&self.pipe_path, self.socket_id) {
                Ok(server) => return Ok(server),
                Err(PipeError::AccessDenied) => {
                    tracing::debug!("PipeError::AccessDenied, sleeping... (loop {i})");
                    tokio::time::sleep(RETRY_INTERVAL).await;
                }
                Err(error) => Err(error)?,
            }
        }
        bail!("Tried {NUM_ITERS} times to bind the pipe and failed");
    }
}

#[derive(Debug, thiserror::Error)]
enum PipeError {
    #[error("Access denied - Is another process using this pipe path?")]
    AccessDenied,
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

fn create_pipe_server(
    pipe_path: &str,
    id: SocketId,
) -> Result<named_pipe::NamedPipeServer, PipeError> {
    let mut server_options = named_pipe::ServerOptions::new();
    server_options.first_pipe_instance(true);

    let sd = pipe_dacl(id)
        .context("Failed to build pipe DACL")
        .map_err(PipeError::Other)?
        .build()
        .context("Failed to materialise pipe DACL into a security descriptor")
        .map_err(PipeError::Other)?;
    let mut sa = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: sd.as_raw().0,
        bInheritHandle: false.into(),
    };

    let sa_ptr = &mut sa as *mut _ as *mut c_void;
    // SAFETY: `sa_ptr` is a valid pointer to a fully-initialised
    // `SECURITY_ATTRIBUTES`. The kernel copies the security descriptor during
    // `CreateNamedPipeW`, so `sd` may be dropped after the call returns.
    match unsafe { server_options.create_with_security_attributes_raw(pipe_path, sa_ptr) } {
        Ok(x) => Ok(x),
        Err(err) if err.kind() == std::io::ErrorKind::PermissionDenied => {
            Err(PipeError::AccessDenied)
        }
        Err(err) => Err(anyhow::Error::from(err).into()),
    }
}

/// Build the DACL that should protect the pipe for `id`.
///
/// - **Tunnel pipe** (`SocketId::Tunnel`): owned by `LocalSystem`, must be
///   reachable by the GUI's package SID. When the sparse-MSIX package
///   registers successfully (Win10 21H2+ in practice), the kernel attaches the
///   package SID to every `Firezone.exe` token and the strict ACE is the only
///   thing that lets the GUI talk to the service. On legacy Win10 builds the
///   package SID isn't attached so we fall back to a `BUILTIN\Users` ACE; that
///   matches the pre-existing posture for those targets. Debug builds always
///   include `BU` so the `gui-smoke-test` can talk to its in-process Tunnel
///   subprocess.
/// - **GUI pipe** (`SocketId::Gui`): the GUI listens, not the Tunnel.
///   Restrict to the package SID *and* the current logon session so other
///   user-mode processes on the same machine — even ones that somehow obtain
///   the package SID — can't drop deep-links into our queue.
/// - **Test pipe** (`SocketId::Test`): permissive, used by unit tests that
///   run as the current user.
fn pipe_dacl(id: SocketId) -> Result<PipeDacl> {
    let pkg_active = package_identity_active();
    let mut dacl = PipeDacl::new()
        .allow(FileRights::FullAccess, Trustee::local_system())
        .allow(FileRights::FullAccess, Trustee::builtin_administrators());

    match id {
        SocketId::Tunnel => {
            if pkg_active {
                dacl = dacl.allow(FileRights::ReadWrite, crate::PACKAGE_TRUSTEE.clone());
            }
            // Older-Win10 fallback OR debug build keeps `BUILTIN\Users`
            // access — required for the smoke test (debug-mode subprocess
            // doesn't get a package SID even on supported OS builds because
            // it isn't launched through the MSIX activation path).
            if !pkg_active || cfg!(debug_assertions) {
                dacl = dacl.allow(FileRights::ReadWrite, Trustee::builtin_users());
            }
        }
        SocketId::Gui => {
            if pkg_active {
                // Package SID + logon-session conditional ACE. The conditional
                // ACE pins access to the specific interactive logon that owns
                // this GUI process; another user on the same machine can't
                // reach the pipe even if they somehow inherited the package
                // SID.
                let scope = Trustee::current_logon().or_else(|_| Trustee::current_user())?;
                dacl = dacl.allow_if_member_of(
                    FileRights::ReadWrite,
                    crate::PACKAGE_TRUSTEE.clone(),
                    scope,
                );
            } else {
                // Legacy fallback — same as pre-hardening behaviour for the
                // GUI pipe.
                dacl = dacl.allow(FileRights::ReadWrite, Trustee::builtin_users());
            }
        }
        #[cfg(test)]
        SocketId::Test(_) => {
            dacl = dacl.allow(FileRights::ReadWrite, Trustee::builtin_users());
        }
    }
    Ok(dacl)
}

/// True iff the current process token carries the Firezone MSIX
/// package SID. Computed once, cached for the rest of the process
/// lifetime — registration state can change only across reboots / MSI
/// (un)install, both of which restart the process.
///
/// The signal we use is `GetCurrentPackageFullName`: it returns
/// `APPMODEL_ERROR_NO_PACKAGE` (15700) when the process has no
/// package identity and `ERROR_INSUFFICIENT_BUFFER` (122) when it
/// does. Anything else (incl. the API being absent on very old
/// Windows builds) is treated as "no package identity".
fn package_identity_active() -> bool {
    static CACHE: OnceLock<bool> = OnceLock::new();
    *CACHE.get_or_init(|| {
        let mut len: u32 = 0;
        // SAFETY: a NULL buffer is the documented sizing pattern. Windows
        // writes into `len` only and treats the buffer ptr as
        // `[out, optional]`.
        let rc = unsafe { GetCurrentPackageFullName(&mut len, std::ptr::null_mut()) };
        // 122 == ERROR_INSUFFICIENT_BUFFER → there *is* a package full name,
        // we just didn't pass enough room. That's what we want.
        let active = rc == 122;
        tracing::debug!(rc, active, "GetCurrentPackageFullName probe");
        active
    })
}

windows_link::link!("kernel32.dll" "system" fn GetCurrentPackageFullName(
    packagefullnamelength: *mut u32,
    packagefullname: *mut u16
) -> u32);

/// Named pipe for an IPC connection
fn ipc_path(id: SocketId) -> String {
    let name = match id {
        SocketId::Tunnel => format!("{}_tunnel.ipc", crate::BUNDLE_ID),
        // Embed a per-user hash so multiple interactive sessions on the same
        // host (RDP / fast user switching) don't fight for the same pipe
        // name. The salt is the current-user SID, so its 16-hex-char SHA-256
        // prefix is stable for the user but opaque to onlookers.
        SocketId::Gui => format!("{}_gui_{}.ipc", crate::BUNDLE_ID, current_user_hash()),
        #[cfg(test)]
        SocketId::Test(id) => format!("{}_test_{id}.ipc", crate::BUNDLE_ID),
    };
    named_pipe_path(&name)
}

/// 16 lowercase hex chars derived from the current user's SID, cached
/// for the process lifetime. Falls back to a fixed placeholder if the
/// token query fails (services, smoke-test rigs) so the GUI pipe
/// still has *some* path.
fn current_user_hash() -> &'static str {
    static CACHE: OnceLock<String> = OnceLock::new();
    CACHE.get_or_init(|| {
        let sid = Trustee::current_user()
            .map(|t| t.as_sddl_str().to_owned())
            .unwrap_or_else(|err| {
                tracing::warn!(?err, "Couldn't resolve current-user SID; using fallback");
                "anonymous".to_owned()
            });
        let digest = Sha256::digest(sid.as_bytes());
        hex::encode(&digest[..8])
    })
}

/// Returns a valid name for a Windows named pipe
///
/// # Arguments
///
/// * `id` - BUNDLE_ID, e.g. `dev.firezone.client`
///
/// Public because the GUI Client reuses this for deep links. Eventually that code
/// will be de-duped into this code.
pub fn named_pipe_path(id: &str) -> String {
    format!(r"\\.\pipe\{id}")
}

#[cfg(test)]
mod tests {
    use super::{Server, SocketId};
    use anyhow::Context as _;
    use futures::StreamExt;

    #[test]
    fn named_pipe_path() {
        assert_eq!(
            super::named_pipe_path("dev.firezone.client"),
            r"\\.\pipe\dev.firezone.client"
        );
    }

    #[test]
    fn ipc_path() {
        assert!(super::ipc_path(SocketId::Tunnel).starts_with(r"\\.\pipe\"));
        assert!(super::ipc_path(SocketId::Gui).starts_with(r"\\.\pipe\"));
    }

    #[test]
    fn pipe_dacl_for_tunnel_renders() {
        // The Test variant of `pipe_dacl` doesn't depend on package
        // identity — that's the path the unit test below exercises.
        let sddl = super::pipe_dacl(SocketId::Test(0))
            .expect("pipe_dacl should succeed for test sockets")
            .to_sddl();
        assert!(sddl.starts_with("D:P"), "{sddl}");
        assert!(sddl.contains("SY"), "{sddl}");
        assert!(sddl.contains("BA"), "{sddl}");
        assert!(sddl.contains("BU"), "{sddl}");
    }

    #[tokio::test]
    async fn single_instance() -> anyhow::Result<()> {
        let _guard = logging::test("trace");
        const ID: SocketId = SocketId::Test(0x1A6FE1F6);
        let mut server_1 = Server::new(ID)?;
        let pipe_path = server_1.pipe_path.clone();

        tokio::spawn(async move {
            let (mut rx, _tx) = server_1.next_client_split::<(), ()>().await?;
            rx.next().await;
            Ok::<_, anyhow::Error>(())
        });

        let (_rx, _tx) =
            crate::ipc::connect::<(), ()>(ID, crate::ipc::ConnectOptions::default()).await?;

        match super::create_pipe_server(&pipe_path, ID) {
            Err(super::PipeError::AccessDenied) => {}
            Err(error) => {
                Err(error).context("Expected `PipeError::AccessDenied` but got another error")?
            }
            Ok(_) => anyhow::bail!("Expected `PipeError::AccessDenied` but got `Ok`"),
        }
        Ok(())
    }
}
