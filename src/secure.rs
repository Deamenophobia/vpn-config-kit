use anyhow::{Context, Result, ensure};
use std::{
    fs::{self, File, OpenOptions},
    io::Write,
    path::Path,
};

pub fn directory(path: &Path) -> Result<()> {
    ensure!(path.is_absolute(), "private directory must be absolute");
    // Reject symlink/reparse paths, including ancestors, before opening state.
    for part in path.ancestors() {
        if let Ok(m) = fs::symlink_metadata(part) {
            ensure!(
                !is_link(&m),
                "symlink/reparse directories are not supported"
            );
        }
    }
    if !path.exists() {
        let builder = fs::DirBuilder::new();
        #[cfg(unix)]
        let mut builder = builder;
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        builder
            .create(path)
            .context("create private directory (parent must exist)")?;
        #[cfg(windows)]
        restrict_windows(path, true)?;
    }
    ensure!(
        fs::symlink_metadata(path)?.is_dir(),
        "private path must be a directory"
    );
    check_mode(path, true)
}
fn is_link(m: &fs::Metadata) -> bool {
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        m.file_attributes() & 0x400 != 0
    }
    #[cfg(not(windows))]
    {
        m.file_type().is_symlink()
    }
}
pub fn check_mode(path: &Path, dir: bool) -> Result<()> {
    let m = fs::symlink_metadata(path)?;
    ensure!(!is_link(&m), "symlink/reparse files are not supported");
    ensure!(
        if dir { m.is_dir() } else { m.is_file() },
        "unexpected private path type"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        ensure!(
            m.mode() & 0o077 == 0 && m.uid() == nix::unistd::geteuid().as_raw(),
            "private files/directories must be owned by current user with mode 0600/0700"
        );
        if !dir {
            ensure!(
                m.nlink() == 1,
                "hard-linked private files are not supported"
            );
        }
    }
    #[cfg(windows)]
    {
        // Pass paths via the child environment, never through PowerShell source interpolation.
        const CHECK: &str = r#"$ErrorActionPreference='Stop'; $a=if([System.IO.Directory]::Exists($env:VPN_CONFIG_KIT_PRIVATE_PATH)){[System.IO.Directory]::GetAccessControl($env:VPN_CONFIG_KIT_PRIVATE_PATH)}else{[System.IO.File]::GetAccessControl($env:VPN_CONFIG_KIT_PRIVATE_PATH)}; $u=[System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value; $owner=$a.GetOwner([System.Security.Principal.SecurityIdentifier]).Value; if($owner -ne $u){exit 1}; foreach($r in $a.GetAccessRules($true,$true,[System.Security.Principal.SecurityIdentifier])){if($r.AccessControlType -eq 'Allow' -and $r.IdentityReference.Value -notin @($u,'S-1-5-18','S-1-5-32-544')){exit 1}}; exit 0"#;
        let mut command = std::process::Command::new("powershell.exe");
        command
            .args(["-NoProfile", "-NonInteractive", "-Command", CHECK])
            .env("VPN_CONFIG_KIT_PRIVATE_PATH", path);
        let ok = crate::runtime::run_command(command, None, std::time::Duration::from_secs(10));
        ensure!(
            ok.is_ok(),
            "private path must be owned by current user and permit only current user, SYSTEM and Administrators; create a dedicated private directory"
        );
    }
    Ok(())
}
#[cfg(windows)]
fn restrict_windows(path: &Path, dir: bool) -> Result<()> {
    // The CSV username may be OEM encoded; ask only for the ASCII SID using a fixed expression.
    let output = crate::runtime::run(
        "powershell.exe",
        &[
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            "[System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value",
        ],
        None,
        std::time::Duration::from_secs(10),
    )?;
    let sid = output
        .trim()
        .split(',')
        .next_back()
        .unwrap_or("")
        .trim_matches('"');
    ensure!(
        sid.starts_with("S-1-")
            && sid
                .bytes()
                .all(|b| b.is_ascii_digit() || b == b'-' || b == b'S'),
        "invalid Windows user SID"
    );
    let grant = format!("*{sid}:{}F", if dir { "(OI)(CI)" } else { "" });
    // Elevated Windows processes can default the owner to Administrators.
    // Assign the current user explicitly rather than weakening the ownership check.
    // Suppress localized stdout while retaining each checked native exit code.
    const RESTRICT: &str = r#"
$ErrorActionPreference='Stop'
& icacls.exe $env:VPN_CONFIG_KIT_PRIVATE_PATH /inheritance:r /grant:r $env:VPN_CONFIG_KIT_PRIVATE_GRANT | Out-Null
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
$acl=if([System.IO.Directory]::Exists($env:VPN_CONFIG_KIT_PRIVATE_PATH)){[System.IO.Directory]::GetAccessControl($env:VPN_CONFIG_KIT_PRIVATE_PATH)}else{[System.IO.File]::GetAccessControl($env:VPN_CONFIG_KIT_PRIVATE_PATH)}
if ($acl.GetOwner([System.Security.Principal.SecurityIdentifier]).Value -ne $env:VPN_CONFIG_KIT_PRIVATE_OWNER) {
    & icacls.exe $env:VPN_CONFIG_KIT_PRIVATE_PATH /setowner ('*' + $env:VPN_CONFIG_KIT_PRIVATE_OWNER) | Out-Null
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
}
exit 0
"#;
    let mut command = std::process::Command::new("powershell.exe");
    command
        .args(["-NoProfile", "-NonInteractive", "-Command", RESTRICT])
        .env("VPN_CONFIG_KIT_PRIVATE_PATH", path)
        .env("VPN_CONFIG_KIT_PRIVATE_OWNER", sid)
        .env("VPN_CONFIG_KIT_PRIVATE_GRANT", grant);
    crate::runtime::run_command(command, None, std::time::Duration::from_secs(10))
        .context("could not restrict Windows ACL")?;
    Ok(())
}
pub fn create(path: &Path, bytes: &[u8]) -> Result<()> {
    directory(path.parent().context("file needs parent")?)?;
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut f = options
        .open(path)
        .context("create private file (refusing overwrite)")?;
    #[cfg(windows)]
    restrict_windows(path, false)?;
    f.write_all(bytes)?;
    f.sync_all()?;
    sync_parent(path)?;
    Ok(())
}
pub fn atomic_write(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path.parent().context("file needs parent")?;
    directory(parent)?;
    if path.exists() {
        check_mode(path, false)?;
    }
    let mut f = tempfile::NamedTempFile::new_in(parent)?;
    #[cfg(windows)]
    restrict_windows(f.path(), false)?;
    f.write_all(bytes)?;
    f.as_file().sync_all()?;
    f.persist(path)
        .map_err(|_| anyhow::anyhow!("atomic configuration replacement failed"))?;
    sync_parent(path)?;
    Ok(())
}
fn sync_parent(path: &Path) -> Result<()> {
    #[cfg(unix)]
    File::open(path.parent().unwrap())?.sync_all()?;
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}
pub fn read_secret(path: &Path) -> Result<crate::keys::Secret> {
    check_mode(path, false)?;
    ensure!(fs::metadata(path)?.len() <= 128, "key file too large");
    crate::keys::Secret::parse(fs::read_to_string(path).context("read key file")?)
}
pub fn lock(dir: &Path) -> Result<File> {
    directory(dir)?;
    let path = dir.join("operation.lock");
    if !path.exists() {
        match create(&path, b"") {
            Ok(()) => (),
            Err(_) if path.exists() => (),
            Err(e) => return Err(e),
        }
    }
    check_mode(&path, false)?;
    let f = OpenOptions::new().read(true).write(true).open(path)?;
    fs2::FileExt::try_lock_exclusive(&f)
        .context("another gateway operation is running; retry after it finishes")?;
    Ok(f)
}
