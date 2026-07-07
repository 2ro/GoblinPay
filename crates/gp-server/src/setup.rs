//! The `gp-server setup` interactive onboarding wizard.
//!
//! This is the guided, secure path to standing up a till: it asks a handful of
//! questions (all with defaults), generates the SERVICE secrets itself (API
//! token, admin token, webhook secret), has the operator CHOOSE the wallet
//! password (grin-wallet-faithful: entered twice and confirmed to match),
//! displays a fresh 24-word seed once and makes the operator acknowledge they
//! wrote it down, creates the encrypted wallet on the spot, probes a curated
//! node list for a healthy one, writes the env + credential files exactly where
//! the shipped systemd unit looks, and prints the three values to paste into
//! WooCommerce. The operator never invents a bearer token or edits a config
//! file; the one secret they own is the wallet password.
//!
//! Restart mode is the operator's call (default UNATTENDED): the chosen
//! password is host-sealed via a systemd credential so the service
//! auto-restarts, or MANUAL, where nothing is persisted and the operator
//! re-enters the password after every restart (a tmpfs-credential drop-in).
//!
//! The pure parts (secret generation, answer parsing, password/match + restart
//! validation, node selection, the rendered outputs) live in `gp_core::setup`
//! and are unit-tested there. This module is the impure shell: the prompt loop
//! (with hidden password entry), the real network probe, wallet creation, and
//! file writing. It is driven over generic reader/writer handles so the flow
//! can be exercised against a `Cursor` + temp dir in tests.

use std::fs;
use std::io::{BufRead, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use gp_core::config::{Chain, Config};
use gp_core::setup as core_setup;
use gp_core::setup::SetupParams;
use gp_wallet::GpWallet;

/// Seals the wallet password to this host as an encrypted credential at rest.
/// Given the plaintext password and the destination `.cred` path, returns
/// `Ok(true)` when it wrote a ciphertext blob (the secure path), `Ok(false)`
/// when sealing is unavailable on this host (the caller then falls back to the
/// legacy 0400 plaintext file with a loud warning), or `Err` on an unexpected
/// failure. The real implementation shells out to `systemd-creds encrypt`; tests
/// inject a deterministic fake so neither the encrypted nor the fallback path
/// depends on the host's systemd.
pub type Sealer = dyn Fn(&str, &Path) -> Result<bool, String>;

/// Options parsed from `gp-server setup [flags]` in `main.rs`.
pub struct SetupOptions {
    /// `--reconfigure`: proceed even if a wallet/env already exists.
    pub reconfigure: bool,
    /// `--prefix DIR`: reroot every output path under DIR (for tests and
    /// non-root dry runs). Default (None) writes the real systemd layout.
    pub prefix: Option<PathBuf>,
    /// `--node URL`: skip the curated-list probe and use this node as-is
    /// (deterministic runs; the real probe is used when absent).
    pub node_override: Option<String>,
    /// `--batch`: proceed reading piped stdin instead of refusing a non-TTY.
    pub force_run: bool,
    /// Whether stdin is a real terminal (computed by `main`). When it is not a
    /// TTY and `force_run` is false, the wizard prints guidance and exits
    /// rather than hanging on a prompt.
    pub stdin_is_tty: bool,
    /// How the unattended wallet password is sealed at rest. `None` uses the real
    /// `systemd-creds` sealer; tests inject a deterministic fake.
    pub seal: Option<Box<Sealer>>,
}

/// Seal `password` to this host with `systemd-creds encrypt`, writing a ciphertext
/// blob to `dest`. Returns `Ok(false)` (fall back to the plaintext file) when
/// `systemd-creds` is missing or cannot access a host credential key (e.g. an
/// older systemd, or a non-root dry run), so the wizard degrades gracefully
/// instead of failing. The plaintext password is passed on stdin, never as an
/// argv arg (which would be visible in the process table).
fn systemd_creds_seal(password: &str, dest: &Path) -> Result<bool, String> {
    use std::io::Write as _;
    use std::process::{Command, Stdio};

    let mut child = match Command::new("systemd-creds")
        .arg("encrypt")
        .arg("--name=gp_wallet_password")
        .arg("-")
        .arg(dest)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
    {
        Ok(c) => c,
        // No systemd-creds on this host: fall back to the plaintext file.
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(e) => return Err(format!("could not run systemd-creds: {e}")),
    };
    if let Some(mut stdin) = child.stdin.take() {
        stdin
            .write_all(password.as_bytes())
            .map_err(|e| format!("could not pass the password to systemd-creds: {e}"))?;
    }
    let status = child
        .wait()
        .map_err(|e| format!("systemd-creds did not complete: {e}"))?;
    // A non-zero exit (commonly: no host credential key without root) is a
    // graceful fallback, not a hard error.
    Ok(status.success())
}

/// What the wizard does about the wallet seed on this run.
enum SeedPlan {
    /// No wallet yet; a fresh seed was generated (show it once).
    Fresh(String),
    /// No wallet yet; the operator pasted an existing seed.
    Pasted(String),
    /// A wallet already exists (reconfigure); keep its seed and password.
    Existing,
}

/// The resolved filesystem layout the wizard writes to. Defaults match the
/// shipped `gp-server.service` (its `EnvironmentFile`, its `LoadCredential`
/// source, and its `StateDirectory`); `--prefix` reroots all of them.
struct Paths {
    env_file: PathBuf,
    secrets_dir: PathBuf,
    /// The legacy PLAINTEXT 0400 wallet-password file (unattended fallback when
    /// `systemd-creds` is unavailable).
    wallet_password_file: PathBuf,
    /// The host-SEALED (ciphertext) wallet-password credential
    /// (`wallet_password.cred`), written in the encrypted-unattended default.
    encrypted_cred_file: PathBuf,
    data_dir: PathBuf,
    db_path: PathBuf,
    /// The MANUAL-mode systemd drop-in (`gp-server.service.d/manual.conf`): its
    /// presence is also how a reconfigure detects the till is in manual mode.
    dropin_file: PathBuf,
    /// The encrypted-unattended systemd drop-in
    /// (`gp-server.service.d/encrypted.conf`), switching the unit to
    /// `LoadCredentialEncrypted`.
    encrypted_dropin_file: PathBuf,
    /// The tmpfs credential the MANUAL mode reads the password from at start.
    runtime_password_file: PathBuf,
}

impl Paths {
    fn resolve(prefix: Option<&Path>) -> Paths {
        let join = |abs: &str| match prefix {
            Some(p) => p.join(abs.trim_start_matches('/')),
            None => PathBuf::from(abs),
        };
        let secrets_dir = join("etc/goblinpay/secrets");
        let dropin_dir = "etc/systemd/system/gp-server.service.d";
        Paths {
            env_file: join("etc/goblinpay.env"),
            wallet_password_file: secrets_dir.join("wallet_password"),
            encrypted_cred_file: secrets_dir.join("wallet_password.cred"),
            secrets_dir,
            data_dir: join("var/lib/goblinpay/gp-data"),
            db_path: join("var/lib/goblinpay/goblinpay.db"),
            dropin_file: join(&format!("{dropin_dir}/manual.conf")),
            encrypted_dropin_file: join(&format!("{dropin_dir}/encrypted.conf")),
            runtime_password_file: join(core_setup::RUNTIME_WALLET_PASSWORD_FILE),
        }
    }
}

/// RAII guard that disables terminal echo on stdin for its lifetime, restoring
/// the previous state on drop. Used so a typed wallet password is not shown.
/// A no-op (and harmless) when stdin is not a real terminal.
struct EchoOff {
    fd: std::os::unix::io::RawFd,
    orig: Option<libc::termios>,
}

impl EchoOff {
    fn new() -> EchoOff {
        use std::os::unix::io::AsRawFd;
        let fd = std::io::stdin().as_raw_fd();
        let orig = unsafe {
            let mut t: libc::termios = std::mem::zeroed();
            if libc::tcgetattr(fd, &mut t) == 0 {
                let mut modt = t;
                modt.c_lflag &= !libc::ECHO;
                let _ = libc::tcsetattr(fd, libc::TCSANOW, &modt);
                Some(t)
            } else {
                None
            }
        };
        EchoOff { fd, orig }
    }
}

impl Drop for EchoOff {
    fn drop(&mut self) {
        if let Some(orig) = self.orig {
            unsafe {
                let _ = libc::tcsetattr(self.fd, libc::TCSANOW, &orig);
            }
        }
    }
}

/// Read one line as a secret. When `hidden` (a real TTY), terminal echo is off
/// for the read so the password is not shown; the Enter keystroke is not echoed
/// either, so we print the newline ourselves. Reads through the SAME `input`
/// reader in both cases (no second stdin handle, so no bytes are lost). Returns
/// `None` on EOF (exhausted scripted input / closed pipe).
fn read_secret_line<R: BufRead, W: Write>(
    input: &mut R,
    out: &mut W,
    hidden: bool,
) -> Result<Option<String>, String> {
    if hidden {
        let _echo_off = EchoOff::new();
        let line = read_line_opt(input)?;
        drop(_echo_off);
        writeln!(out).map_err(io_err)?;
        Ok(line)
    } else {
        read_line_opt(input)
    }
}

/// Run the wizard. Reads answers from `input`, writes prompts/output to `out`.
/// Returns `Err` with a human message on any failure (the caller exits nonzero).
pub fn run<R: BufRead, W: Write>(
    mut input: R,
    out: &mut W,
    opts: &SetupOptions,
) -> Result<(), String> {
    let paths = Paths::resolve(opts.prefix.as_deref());

    // Non-interactive guard: a piped/redirected stdin would make every prompt
    // read EOF and silently take defaults (or hang), so refuse unless the
    // operator explicitly opts into batch mode.
    if !opts.stdin_is_tty && !opts.force_run {
        writeln!(
            out,
            "gp-server setup is interactive and stdin is not a terminal.\n\
             Run it in a real terminal:  sudo gp-server setup\n\
             (or pass --batch to read scripted answers from stdin.)"
        )
        .map_err(io_err)?;
        return Err("not a TTY; guidance printed".into());
    }

    // Re-run safety: never clobber an existing wallet or env without an
    // explicit --reconfigure. The seed at rest is the money; refuse loudly.
    let seed_path = GpWallet::seed_path(&paths.data_dir);
    if !opts.reconfigure && (seed_path.exists() || paths.env_file.exists()) {
        return Err(format!(
            "a GoblinPay wallet or config already exists ({} / {}). \
             Refusing to overwrite it. Re-run with --reconfigure only if you are \
             sure (this does NOT delete the encrypted seed).",
            seed_path.display(),
            paths.env_file.display()
        ));
    }

    writeln!(out, "GoblinPay setup").map_err(io_err)?;
    writeln!(
        out,
        "Answer a few questions. You choose your wallet password and record your\n\
         seed; the service tokens and everything else are generated for you.\n"
    )
    .map_err(io_err)?;

    // Q1: public URL of the till (required). Accepts either a subdomain
    // (needs one DNS record) OR a reverse-proxied path on the shop's existing
    // domain (zero new DNS records), so the least-technical operator can avoid
    // touching DNS entirely.
    writeln!(
        out,
        "1) Public address customers reach this till at (https URL).\n\
         \x20  Either a subdomain (e.g. https://pay.myshop.com) or a path on your\n\
         \x20  existing shop domain (e.g. https://myshop.com/pay) if you would\n\
         \x20  rather add ZERO new DNS records and reverse-proxy a path instead."
    )
    .map_err(io_err)?;
    let public_url = prompt_required(
        &mut input,
        out,
        core_setup::normalize_url,
        "   your till URL",
    )?;

    // Q2: shop URL -> webhook URL (required).
    let webhook_url = prompt_required(
        &mut input,
        out,
        core_setup::webhook_url_from_shop,
        "2) Your shop's website URL (the WooCommerce site), e.g. https://myshop.com",
    )?;

    // Q3: local listen address (default loopback). It stays behind the reverse
    // proxy, so the default is right for almost everyone; pressing Enter takes
    // it.
    writeln!(
        out,
        "3) Local address the server listens on. Keep it loopback behind your\n\
         \x20  reverse proxy unless you know you need otherwise. [127.0.0.1:8080]"
    )
    .map_err(io_err)?;
    write!(out, "   > ").map_err(io_err)?;
    out.flush().map_err(io_err)?;
    let bind = core_setup::normalize_bind(&read_line(&mut input)?);

    // Q4: Grin node URL (read-only: confirmations + balance). An explicit
    // `--node` override skips the question; otherwise pressing Enter auto-picks a
    // healthy node from the curated list, or the operator can name their own.
    let node_url = resolve_node(&mut input, out, opts)?;

    // Hidden password entry only when stdin is a real terminal; scripted/batch
    // runs (and tests) read the password as plain lines from `input`.
    let hidden = opts.stdin_is_tty;

    // Q5-Q7 concern the wallet secrets and are only asked for a NEW wallet. On a
    // --reconfigure with an existing wallet we keep the seed and password at rest
    // untouched (that is the money), so prompting for them would be a trap. The
    // restart mode IS still offered on reconfigure, defaulting to the till's
    // current mode, so it is preserved unless the operator explicitly changes it.
    let wallet_exists = seed_path.exists();
    let (seed_plan, chosen_password, restart_mode) = if wallet_exists {
        writeln!(
            out,
            "Existing till wallet found; keeping its seed and password."
        )
        .map_err(io_err)?;
        // Detect the current restart mode from disk: the MANUAL-mode drop-in
        // exists only when the till was set up manual. Prompt with it as the
        // default so pressing Enter preserves it (this was previously hardcoded
        // to unattended, which silently rewrote a manual till's config).
        let current_mode = if paths.dropin_file.exists() {
            core_setup::RestartMode::Manual
        } else {
            core_setup::RestartMode::Unattended
        };
        let mode = prompt_restart_mode(&mut input, out, None, current_mode)?;
        (SeedPlan::Existing, None, mode)
    } else {
        // Q5: the operator CHOOSES the wallet password (grin-wallet-faithful:
        // entered twice, must match). It encrypts the seed at rest.
        let password = prompt_wallet_password(&mut input, out, hidden)?;

        // Q6: the seed. Fresh (generate, show ONCE, acknowledge) or paste an
        // existing recovery phrase (acknowledge the written backup). Both paths
        // are gated behind an explicit acknowledgement, like grin-wallet init.
        writeln!(
            out,
            "6) Grin seed: press Enter to generate a FRESH 24-word till seed,\n\
             \x20  or paste your existing recovery phrase."
        )
        .map_err(io_err)?;
        write!(out, "   > ").map_err(io_err)?;
        out.flush().map_err(io_err)?;
        let seed_line = read_line(&mut input)?;
        let plan = if seed_line.trim().is_empty() {
            let entropy = core_setup::gen_entropy_32();
            let m = gp_wallet::mnemonic_from_entropy(&entropy)
                .map_err(|e| format!("could not generate a seed: {e}"))?;
            writeln!(
                out,
                "\n============================================================\n\
                 WRITE THIS DOWN. This is your till's seed, its money backup.\n\
                 It is shown ONCE and never again. Store it offline, safely.\n\
                 ------------------------------------------------------------\n\
                 {m}\n\
                 ============================================================"
            )
            .map_err(io_err)?;
            require_ack(
                &mut input,
                out,
                "Have you written down these 24 words? Type yes to continue",
            )?;
            SeedPlan::Fresh(m)
        } else {
            let m = seed_line.trim().to_string();
            require_ack(
                &mut input,
                out,
                "Keep your written backup of this seed safe. Type yes to continue",
            )?;
            SeedPlan::Pasted(m)
        };

        // Q7: restart mode (owner ruling: offer both, default UNATTENDED).
        let mode = prompt_restart_mode(
            &mut input,
            out,
            Some(7),
            core_setup::RestartMode::Unattended,
        )?;

        (plan, Some(password), mode)
    };

    // Q8: currencies (default usd).
    writeln!(out, "8) Currencies your shop prices in? [usd]").map_err(io_err)?;
    write!(out, "   > ").map_err(io_err)?;
    out.flush().map_err(io_err)?;
    let currencies = core_setup::parse_currencies(&read_line(&mut input)?);

    // Q9: advanced grin1/Tor rail (default no).
    writeln!(
        out,
        "9) (advanced) Also accept payments from any Grin wallet over Tor? [y/N]"
    )
    .map_err(io_err)?;
    write!(out, "   > ").map_err(io_err)?;
    out.flush().map_err(io_err)?;
    let grin1_rail = core_setup::parse_yes_no(&read_line(&mut input)?, false);

    // Generate the SERVICE bearer secrets (the operator never types or invents
    // these). The wallet password is the operator's own choice, captured above.
    let api_token = core_setup::gen_api_token();
    let admin_token = core_setup::gen_admin_token();
    let webhook_secret = core_setup::gen_webhook_secret();

    // Create (or, on reconfigure, reopen) the encrypted wallet. Creating
    // consumes the seed once: it lives encrypted at rest afterwards, never in
    // the service environment (owner ruling O2). Reopening an existing wallet
    // reuses the password already on file, so a --reconfigure never re-encrypts
    // (which would need the old password) or touches the seed.
    // The at-rest password sealer: the real systemd-creds one in production, a
    // deterministic fake when tests inject it.
    let default_seal: Box<Sealer> = Box::new(systemd_creds_seal);
    let seal: &Sealer = opts.seal.as_deref().unwrap_or(default_seal.as_ref());

    ensure_dir(&paths.data_dir, 0o700)?;
    ensure_dir(&paths.secrets_dir, 0o700)?;
    let (wallet, unattended_encrypted) = match &seed_plan {
        SeedPlan::Existing => {
            // Reopen the existing wallet. Its password may be on the legacy 0400
            // plaintext file (plaintext-unattended tills); the secure encrypted
            // and manual shapes keep no readable password on disk, so prompt for
            // it. A wrong password simply fails the reopen below.
            let password = match fs::read_to_string(&paths.wallet_password_file) {
                Ok(s) => s.trim_end_matches(['\n', '\r']).to_string(),
                Err(_) => {
                    writeln!(
                        out,
                        "This till keeps no readable password on disk. Enter its wallet\n\
                         password to reopen the wallet and reconfigure it."
                    )
                    .map_err(io_err)?;
                    prompt_existing_password(&mut input, out, hidden)?
                }
            };
            writeln!(out, "Reopening the existing till wallet...").map_err(io_err)?;
            let w =
                GpWallet::create_at(&paths.data_dir, None, &password, &node_url, Chain::Mainnet)
                    .map_err(|e| format!("could not reopen the existing wallet: {e}"))?;
            // Re-apply the (possibly changed) restart mode. Preserving the mode
            // leaves these files as they were; switching mode moves the password
            // on/off disk accordingly.
            let enc = apply_restart_persistence(&paths, restart_mode, &password, seal, out)?;
            (w, enc)
        }
        SeedPlan::Fresh(m) | SeedPlan::Pasted(m) => {
            let password = chosen_password
                .as_deref()
                .expect("a new wallet always has an operator-chosen password");
            writeln!(out, "Creating the encrypted till wallet...").map_err(io_err)?;
            let w = GpWallet::create_at(
                &paths.data_dir,
                Some(m),
                password,
                &node_url,
                Chain::Mainnet,
            )
            .map_err(|e| format!("wallet creation failed: {e}"))?;
            let enc = apply_restart_persistence(&paths, restart_mode, password, seal, out)?;
            (w, enc)
        }
    };
    match wallet.slatepack_address() {
        Ok(addr) => writeln!(out, "Wallet ready (address {addr}).").map_err(io_err)?,
        Err(e) => return Err(format!("wallet opened but address read failed: {e}")),
    }

    // Where the service reads the wallet password from at runtime depends on the
    // restart mode: the persistent 0400 file (unattended) or the tmpfs
    // credential the operator populates at each start (manual).
    let wallet_password_file = match restart_mode {
        // Encrypted default: the env points at the runtime (decrypted) credential
        // path systemd populates, matching the unit's %d/gp_wallet_password. It is
        // absent at setup time (so an in-process first run defers to systemctl)
        // and present once the service starts.
        core_setup::RestartMode::Unattended if unattended_encrypted => {
            core_setup::CREDENTIALS_WALLET_PASSWORD_PATH.to_string()
        }
        core_setup::RestartMode::Unattended => paths.wallet_password_file.display().to_string(),
        core_setup::RestartMode::Manual => paths.runtime_password_file.display().to_string(),
    };

    // Render + write the env file (0640) the service loads.
    let params = SetupParams {
        bind,
        public_url: public_url.clone(),
        webhook_url: webhook_url.clone(),
        node_url,
        relays: core_setup::DEFAULT_RELAYS
            .iter()
            .map(|s| s.to_string())
            .collect(),
        currencies,
        grin1_rail,
        api_token,
        admin_token,
        webhook_secret,
        data_dir: paths.data_dir.display().to_string(),
        db_path: paths.db_path.display().to_string(),
        wallet_password_file,
        restart_mode,
        unattended_encrypted,
    };
    write_env_file(&paths.env_file, &params.render_env())?;

    // The seed was already shown once and acknowledged above (fresh) or the
    // operator confirmed their written backup (pasted); a short reminder here.
    writeln!(out).map_err(io_err)?;
    match &seed_plan {
        SeedPlan::Fresh(_) => writeln!(
            out,
            "Seed recorded by you. It was shown once and will not be shown again."
        )
        .map_err(io_err)?,
        SeedPlan::Pasted(_) => writeln!(
            out,
            "Using your existing seed. Keep your written backup of it safe."
        )
        .map_err(io_err)?,
        SeedPlan::Existing => writeln!(
            out,
            "Kept the existing till wallet; its seed and password are unchanged."
        )
        .map_err(io_err)?,
    }

    // Final screen: how to start (per restart mode), and the WooCommerce block.
    writeln!(out, "\nGoblinPay is set up.").map_err(io_err)?;
    match restart_mode {
        core_setup::RestartMode::Unattended if unattended_encrypted => writeln!(
            out,
            "Restart mode: UNATTENDED (encrypted at rest). Start it:\n\
             \x20 sudo systemctl daemon-reload && sudo systemctl start gp-server\n\
             The password is sealed to this host with systemd-creds (ciphertext on\n\
             disk); systemd decrypts it at each start, so the service auto-restarts.\n\
             (Keep the till a small hot float and sweep to your own wallet often:\n\
             a compromise of the RUNNING host still means wallet compromise.)\n"
        )
        .map_err(io_err)?,
        core_setup::RestartMode::Unattended => writeln!(
            out,
            "Restart mode: UNATTENDED (plaintext fallback). Start it:\n\
             \x20 sudo systemctl start gp-server\n\
             systemd-creds was unavailable, so the password is a root-owned 0400\n\
             PLAINTEXT file. It will auto-restart, but the key is plaintext at rest.\n\
             (Keep the till a small hot float and sweep to your own wallet often:\n\
             a full-machine compromise means wallet compromise.)\n"
        )
        .map_err(io_err)?,
        core_setup::RestartMode::Manual => writeln!(
            out,
            "Restart mode: MANUAL. Nothing sensitive is on disk; supply the\n\
             password at each start (and after every reboot):\n\
             \x20 sudo install -d -m0700 /run/goblinpay\n\
             \x20 systemd-ask-password \"GoblinPay wallet password:\" \\\n\
             \x20   | sudo install -m0400 /dev/stdin {rt}\n\
             \x20 sudo systemctl daemon-reload && sudo systemctl start gp-server\n\
             The service will NOT come back on its own after a restart until you\n\
             re-enter the password. Maximum protection against disk/machine theft.\n",
            rt = paths.runtime_password_file.display()
        )
        .map_err(io_err)?,
    }
    writeln!(out, "{}", params.woo_paste_block()).map_err(io_err)?;

    // Reverse-proxy hint. GoblinPay binds loopback (127.0.0.1:8080 by default),
    // so it needs a TLS-terminating proxy in front. Two shapes, matching the
    // two till-URL answers: a subdomain, or a zero-DNS path on the shop domain.
    let base = core_setup::base_path(&public_url);
    writeln!(
        out,
        "\nPut it behind your reverse proxy (it binds 127.0.0.1:8080):"
    )
    .map_err(io_err)?;
    if base.is_empty() {
        writeln!(
            out,
            "  Subdomain ({public_url}) - proxy the whole host to the till, e.g. nginx:\n\
             \x20   location / {{ proxy_pass http://127.0.0.1:8080; }}\n\
             \x20 (or Caddy:  {public_url} {{ reverse_proxy 127.0.0.1:8080 }} )"
        )
        .map_err(io_err)?;
    } else {
        writeln!(
            out,
            "  Path on your shop domain ({public_url}) - ZERO new DNS records; proxy\n\
             \x20 just the '{base}' path to the till, stripping the prefix, e.g. nginx:\n\
             \x20   location {base}/ {{ proxy_pass http://127.0.0.1:8080/; }}\n\
             \x20 (the trailing slash on proxy_pass strips '{base}' so the till's own\n\
             \x20  routes line up; the pages already emit '{base}'-prefixed links.)"
        )
        .map_err(io_err)?;
    }

    match restart_mode {
        core_setup::RestartMode::Unattended if unattended_encrypted => writeln!(
            out,
            "\nWrote {} and {} (sealed credential, ciphertext) plus the\n\
             encrypted.conf drop-in. No plaintext wallet password is stored on disk.",
            paths.env_file.display(),
            paths.encrypted_cred_file.display()
        )
        .map_err(io_err)?,
        core_setup::RestartMode::Unattended => writeln!(
            out,
            "\nWrote {} and {} (PLAINTEXT password file, mode 0400).",
            paths.env_file.display(),
            paths.wallet_password_file.display()
        )
        .map_err(io_err)?,
        core_setup::RestartMode::Manual => writeln!(
            out,
            "\nWrote {} and {} (manual-mode drop-in, mode 0644). No wallet\n\
             password is stored on disk.",
            paths.env_file.display(),
            paths.dropin_file.display()
        )
        .map_err(io_err)?,
    }

    Ok(())
}

/// Prompt until `parse` accepts a non-empty answer, reprinting the error.
fn prompt_required<R: BufRead, W: Write, T, F: Fn(&str) -> Result<T, String>>(
    input: &mut R,
    out: &mut W,
    parse: F,
    question: &str,
) -> Result<T, String> {
    loop {
        writeln!(out, "{question}").map_err(io_err)?;
        write!(out, "   > ").map_err(io_err)?;
        out.flush().map_err(io_err)?;
        let line = read_line(input)?;
        match parse(&line) {
            Ok(v) => return Ok(v),
            Err(e) => {
                writeln!(out, "   ! {e}\n").map_err(io_err)?;
                // In batch mode there is no human to correct the input; fail
                // fast instead of looping forever on the same EOF-backed read.
                if line.is_empty() {
                    return Err(format!("no answer provided: {e}"));
                }
            }
        }
    }
}

/// Read one line, stripping the trailing newline. An empty read (EOF) yields an
/// empty string so batch runs terminate cleanly.
fn read_line<R: BufRead>(input: &mut R) -> Result<String, String> {
    Ok(read_line_opt(input)?.unwrap_or_default())
}

/// Read one line, distinguishing EOF (`None`) from an empty typed line
/// (`Some("")`). Loops that must not spin on exhausted input (password, seed
/// acknowledgement) use this to fail cleanly at end of input.
fn read_line_opt<R: BufRead>(input: &mut R) -> Result<Option<String>, String> {
    let mut buf = String::new();
    let n = input.read_line(&mut buf).map_err(io_err)?;
    if n == 0 {
        return Ok(None);
    }
    Ok(Some(buf.trim_end_matches(['\n', '\r']).to_string()))
}

/// Prompt the operator to CHOOSE their wallet password, entered twice and
/// confirmed to match (grin-wallet-faithful). Re-prompts on an empty password
/// or a mismatch; fails cleanly at end of input (batch/scripted runs).
fn prompt_wallet_password<R: BufRead, W: Write>(
    input: &mut R,
    out: &mut W,
    hidden: bool,
) -> Result<String, String> {
    writeln!(
        out,
        "3) Choose a password to encrypt this till's wallet.\n\
         \x20  You will enter it to unlock the wallet; it is NOT recoverable — if you\n\
         \x20  forget it, restore the till from its 24-word seed. Entered twice."
    )
    .map_err(io_err)?;
    loop {
        write!(out, "   new password > ").map_err(io_err)?;
        out.flush().map_err(io_err)?;
        let first = match read_secret_line(input, out, hidden)? {
            Some(s) => s,
            None => return Err("no wallet password provided (end of input)".into()),
        };
        if let Err(e) = core_setup::validate_password(&first) {
            writeln!(out, "   ! {e}\n").map_err(io_err)?;
            continue;
        }
        write!(out, "   repeat password > ").map_err(io_err)?;
        out.flush().map_err(io_err)?;
        let second = match read_secret_line(input, out, hidden)? {
            Some(s) => s,
            None => return Err("wallet password not confirmed (end of input)".into()),
        };
        if core_setup::passwords_match(&first, &second) {
            return Ok(first);
        }
        writeln!(out, "   ! passwords do not match; try again\n").map_err(io_err)?;
    }
}

/// Prompt once for an EXISTING wallet password (reconfiguring a till that keeps
/// no readable password on disk: the encrypted or manual shapes). No confirm
/// entry: correctness is checked by the wallet reopen that follows, which fails
/// on a wrong password. Fails cleanly at end of input (batch/scripted runs).
fn prompt_existing_password<R: BufRead, W: Write>(
    input: &mut R,
    out: &mut W,
    hidden: bool,
) -> Result<String, String> {
    loop {
        write!(out, "   wallet password > ").map_err(io_err)?;
        out.flush().map_err(io_err)?;
        match read_secret_line(input, out, hidden)? {
            None => return Err("no wallet password provided (end of input)".into()),
            Some(s) if !s.is_empty() => return Ok(s),
            Some(_) => writeln!(out, "   ! password must not be empty\n").map_err(io_err)?,
        }
    }
}

/// Require an explicit yes/y acknowledgement before proceeding (the operator
/// confirming they wrote the seed down, like grin-wallet init). Re-prompts on
/// any other non-empty answer; fails cleanly at end of input.
fn require_ack<R: BufRead, W: Write>(
    input: &mut R,
    out: &mut W,
    prompt: &str,
) -> Result<(), String> {
    loop {
        writeln!(out, "{prompt}").map_err(io_err)?;
        write!(out, "   > ").map_err(io_err)?;
        out.flush().map_err(io_err)?;
        match read_line_opt(input)? {
            None => {
                return Err(
                    "seed not acknowledged (end of input); type yes to confirm you \
                     wrote it down"
                        .into(),
                )
            }
            Some(line) if core_setup::parse_ack(&line) => return Ok(()),
            Some(_) => {
                writeln!(
                    out,
                    "   ! please type yes once you have written the seed down\n"
                )
                .map_err(io_err)?;
            }
        }
    }
}

/// Resolve the Grin node URL. An explicit `--node` override is used as-is (no
/// prompt, for deterministic/offline runs and tests). Otherwise the operator is
/// asked: pressing Enter probes the curated list for the first healthy node (the
/// sensible default), or they can name their own `http(s)://` node.
fn resolve_node<R: BufRead, W: Write>(
    input: &mut R,
    out: &mut W,
    opts: &SetupOptions,
) -> Result<String, String> {
    if let Some(url) = &opts.node_override {
        writeln!(out, "Using Grin node {url} (override).").map_err(io_err)?;
        return Ok(url.clone());
    }
    writeln!(
        out,
        "4) Grin node for confirmations and balance (read-only). Press Enter to\n\
         \x20  auto-pick a healthy node from the curated list, or enter your own\n\
         \x20  https:// node."
    )
    .map_err(io_err)?;
    write!(out, "   > ").map_err(io_err)?;
    out.flush().map_err(io_err)?;
    let answer = read_line(input)?;
    if answer.trim().is_empty() {
        writeln!(out, "Probing curated Grin nodes for a healthy one...").map_err(io_err)?;
        match core_setup::select_node(core_setup::CURATED_NODES, gp_wallet::probe_node) {
            Some(url) => {
                writeln!(out, "Using Grin node {url}.").map_err(io_err)?;
                Ok(url)
            }
            None => Err(
                "none of the curated Grin nodes answered. Check this host's \
                 network, or pass --node <url> to use a node you trust."
                    .into(),
            ),
        }
    } else {
        let url = core_setup::normalize_url(&answer)?;
        writeln!(out, "Using Grin node {url}.").map_err(io_err)?;
        Ok(url)
    }
}

/// Prompt for the restart mode, offering both options and defaulting to `default`
/// (UNATTENDED for a fresh setup; the till's current mode on reconfigure, so
/// pressing Enter preserves it). `number`, when set, prefixes the question so it
/// lines up with the numbered fresh-setup flow.
fn prompt_restart_mode<R: BufRead, W: Write>(
    input: &mut R,
    out: &mut W,
    number: Option<u8>,
    default: core_setup::RestartMode,
) -> Result<core_setup::RestartMode, String> {
    let (u_tag, m_tag, hint) = match default {
        core_setup::RestartMode::Unattended => (" (default)", "", "[1]"),
        core_setup::RestartMode::Manual => ("", " (default)", "[2]"),
    };
    let lead = match number {
        Some(n) => format!("{n}) "),
        None => String::new(),
    };
    writeln!(
        out,
        "{lead}After a reboot, how should the till restart?\n\
         \x20  [1] Unattended{u_tag}: your password is sealed to THIS host, so the\n\
         \x20      service auto-restarts. Honest trade-off: whoever fully controls\n\
         \x20      this machine controls the wallet; keep it a small hot float and\n\
         \x20      sweep to your own wallet regularly.\n\
         \x20  [2] Manual{m_tag}: the password lives only in your head; you re-enter\n\
         \x20      it after every restart. Maximum protection against disk/machine theft."
    )
    .map_err(io_err)?;
    write!(out, "   > {hint} ").map_err(io_err)?;
    out.flush().map_err(io_err)?;
    Ok(core_setup::parse_restart_mode_default(
        &read_line(input)?,
        default,
    ))
}

/// Persist the wallet password per restart mode, idempotently, so this also
/// handles a reconfigure that SWITCHES modes. Returns whether an UNATTENDED
/// password was ENCRYPTED at rest (the secure default) versus the plaintext
/// fallback; the flag is meaningless (false) for MANUAL.
///
/// UNATTENDED first tries to SEAL the chosen password to this host with
/// `systemd-creds` (ciphertext at rest, read by `LoadCredentialEncrypted`); no
/// plaintext wallet password ever touches the disk. If sealing is unavailable it
/// falls back to the legacy root-owned 0400 PLAINTEXT file (read by the base
/// unit's `LoadCredential`) with a loud warning. MANUAL keeps NOTHING sensitive
/// on disk: it writes only the drop-in that repoints the credential to a tmpfs
/// path the operator populates by hand. Every stale artifact of the other shapes
/// is cleared so a reconfigure that switches modes leaves exactly one in place.
fn apply_restart_persistence<W: Write>(
    paths: &Paths,
    mode: core_setup::RestartMode,
    password: &str,
    seal: &Sealer,
    out: &mut W,
) -> Result<bool, String> {
    match mode {
        core_setup::RestartMode::Unattended => {
            ensure_dir(&paths.secrets_dir, 0o700)?;
            if seal(password, paths.encrypted_cred_file.as_path())? {
                // Encrypted at rest (secure default): write the drop-in that reads
                // the sealed credential, and clear the plaintext + manual shapes.
                let src = paths.encrypted_cred_file.display().to_string();
                write_dropin_file(
                    &paths.encrypted_dropin_file,
                    &core_setup::render_encrypted_dropin(&src),
                )?;
                remove_if_exists(&paths.wallet_password_file)?;
                remove_if_exists(&paths.dropin_file)?;
                Ok(true)
            } else {
                // Fallback: systemd-creds unavailable. Root-owned 0400 plaintext
                // file, matching the base unit's LoadCredential. Warn loudly.
                writeln!(
                    out,
                    "WARNING: systemd-creds is unavailable on this host, so the wallet\n\
                     password could not be encrypted at rest. Falling back to a root-owned\n\
                     0400 PLAINTEXT file ({}). It is off the world-readable env file, but it\n\
                     is still plaintext on disk. For encryption at rest, install systemd >= 250\n\
                     with a host credential key and re-run: sudo gp-server setup --reconfigure",
                    paths.wallet_password_file.display()
                )
                .map_err(io_err)?;
                write_secret_file(&paths.wallet_password_file, password)?;
                remove_if_exists(&paths.encrypted_cred_file)?;
                remove_if_exists(&paths.encrypted_dropin_file)?;
                remove_if_exists(&paths.dropin_file)?;
                Ok(false)
            }
        }
        core_setup::RestartMode::Manual => {
            let runtime_pw = paths.runtime_password_file.display().to_string();
            write_dropin_file(
                &paths.dropin_file,
                &core_setup::render_manual_dropin(&runtime_pw),
            )?;
            remove_if_exists(&paths.wallet_password_file)?;
            remove_if_exists(&paths.encrypted_cred_file)?;
            remove_if_exists(&paths.encrypted_dropin_file)?;
            Ok(false)
        }
    }
}

/// Remove a file if it exists (ignoring a not-found race); used when a
/// reconfigure switches restart mode and the other mode's artifact must go.
fn remove_if_exists(path: &Path) -> Result<(), String> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(format!("cannot remove {}: {e}", path.display())),
    }
}

/// Whether a bare `gp-server` invocation (no subcommand) should offer the
/// first-run wizard. True only for a genuinely fresh, unconfigured install: the
/// ingest service is on (the default) but there is no way to open a wallet yet
/// (no seed at rest, no mnemonic and no wallet password in the environment) and
/// no env file has been written. Every configured deploy fails at least one of
/// these, so the headless boot path is taken exactly as before.
pub fn needs_first_run_setup(cfg: &Config, env_file_exists: bool) -> bool {
    cfg.ingest
        && cfg.mnemonic.is_none()
        && cfg.wallet_password.is_none()
        && !GpWallet::seed_path(Path::new(&cfg.data_dir)).exists()
        && !env_file_exists
}

/// Load a `Config` from the env file the wizard just wrote, so a first run can
/// boot in-process from it (parsing the file directly rather than round-tripping
/// through a systemd `EnvironmentFile` reload). The `*_FILE` secret indirection
/// is honored by `Config::from_lookup`, so an UNATTENDED run resolves the 0400
/// wallet-password file; a MANUAL run has no on-disk password and so returns an
/// error here (the caller then prints how to start the service by hand).
pub fn config_from_written_env(path: &Path) -> Result<Config, String> {
    let contents =
        fs::read_to_string(path).map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    let map: std::collections::HashMap<String, String> =
        core_setup::parse_env_file(&contents).into_iter().collect();
    Config::from_lookup(&|key| map.get(key).cloned())
}

/// Create a directory (and parents) with the given mode.
fn ensure_dir(path: &Path, mode: u32) -> Result<(), String> {
    fs::create_dir_all(path).map_err(|e| format!("cannot create {}: {e}", path.display()))?;
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
        .map_err(|e| format!("cannot chmod {}: {e}", path.display()))
}

/// Write a secret to `path` with mode 0400. Any existing file is removed first:
/// a prior 0400 secret has no write bit even for its owner, so an in-place
/// rewrite (as on a reconfigure) would be denied.
fn write_secret_file(path: &Path, contents: &str) -> Result<(), String> {
    remove_if_exists(path)?;
    fs::write(path, format!("{contents}\n"))
        .map_err(|e| format!("cannot write {}: {e}", path.display()))?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o400))
        .map_err(|e| format!("cannot chmod {}: {e}", path.display()))
}

/// Write the MANUAL-mode systemd drop-in (mode 0644; it holds no secret, only
/// the credential wiring), creating the `.d` directory as needed.
fn write_dropin_file(path: &Path, contents: &str) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|e| format!("cannot create {}: {e}", parent.display()))?;
    }
    fs::write(path, contents).map_err(|e| format!("cannot write {}: {e}", path.display()))?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o644))
        .map_err(|e| format!("cannot chmod {}: {e}", path.display()))
}

/// Write the env file with mode 0640 (root-owned config with bearer tokens).
fn write_env_file(path: &Path, contents: &str) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|e| format!("cannot create {}: {e}", parent.display()))?;
    }
    fs::write(path, contents).map_err(|e| format!("cannot write {}: {e}", path.display()))?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o640))
        .map_err(|e| format!("cannot chmod {}: {e}", path.display()))
}

fn io_err<E: std::fmt::Display>(e: E) -> String {
    format!("io error: {e}")
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;

    /// Self-cleaning temp dir (no extra dev-dep), mirroring gp-wallet's tests.
    struct TempDir(PathBuf);
    impl TempDir {
        fn new(tag: &str) -> TempDir {
            use std::sync::atomic::{AtomicU32, Ordering};
            static N: AtomicU32 = AtomicU32::new(0);
            let p = std::env::temp_dir().join(format!(
                "gp-setup-{tag}-{}-{}",
                std::process::id(),
                N.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir_all(&p).unwrap();
            TempDir(p)
        }
    }
    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn opts_with(prefix: &Path) -> SetupOptions {
        SetupOptions {
            reconfigure: false,
            prefix: Some(prefix.to_path_buf()),
            // Skip the network probe in tests (deterministic, offline).
            node_override: Some("http://127.0.0.1:3413".into()),
            force_run: true,
            stdin_is_tty: false,
            // Force the PLAINTEXT fallback deterministically (independent of the
            // host's systemd), so these tests exercise the 0400-file shape. The
            // encrypted path is covered by its own test with a fake sealer.
            seal: Some(Box::new(|_, _| Ok(false))),
        }
    }

    /// A fake sealer that "succeeds", writing a non-secret marker to the `.cred`
    /// path so the encrypted-unattended shape can be tested without real
    /// systemd-creds (and without ever writing the password to that file).
    fn fake_sealer_ok() -> Box<Sealer> {
        Box::new(|_pw, dest| {
            fs::write(dest, b"(sealed by test)\n").map_err(|e| format!("fake seal failed: {e}"))?;
            Ok(true)
        })
    }

    /// All-zero 32-byte entropy -> the well-known dev seed (24 words). Used only
    /// as a test fixture; never a real till seed.
    const DEV_SEED_24: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";

    #[test]
    fn full_run_writes_files_with_modes_and_paste_block() {
        let dir = TempDir::new("full");
        let opts = opts_with(&dir.0);
        // Answers: public url, shop url, bind (Enter = default; node is skipped
        // via the override), chosen password (twice), paste the dev seed,
        // acknowledge, restart mode (Enter = unattended), currencies, rail.
        let answers = format!(
            "https://pay.myshop.com\nhttps://myshop.com\n\n\
             walletpass1\nwalletpass1\n{DEV_SEED_24}\nyes\n\nusd,eur\nn\n"
        );
        let mut out = Vec::new();
        run(Cursor::new(answers), &mut out, &opts).unwrap();
        let transcript = String::from_utf8(out).unwrap();

        // The env file exists, is 0640, has the couplings, and no seed.
        let paths = Paths::resolve(Some(&dir.0));
        let env = fs::read_to_string(&paths.env_file).unwrap();
        let mode = fs::metadata(&paths.env_file).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o640);
        assert!(env.contains("GP_BIND=127.0.0.1:8080")); // bind default written
        assert!(env.contains("GP_PUBLIC_URL=https://pay.myshop.com"));
        assert!(env.contains("GP_WEBHOOK_URL=https://myshop.com/wp-json/goblinpay/v1/webhook"));
        assert!(env.contains("GP_RELAY_MODE=external"));
        assert!(env.contains("GP_RATE_CURRENCIES=usd,eur"));
        assert!(env.contains("GP_API_TOKEN=gp_live_"));
        assert!(!env.contains("GP_MNEMONIC"));
        assert!(env.contains("#GP_GRIN1_RAIL=on")); // off -> commented

        // The wallet password file exists, mode 0400, and holds exactly the
        // operator-chosen password (not an auto-generated one).
        let pw_mode = fs::metadata(&paths.wallet_password_file)
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(pw_mode, 0o400);
        assert_eq!(
            fs::read_to_string(&paths.wallet_password_file)
                .unwrap()
                .trim_end(),
            "walletpass1"
        );

        // The encrypted seed was created.
        assert!(GpWallet::seed_path(&paths.data_dir).exists());

        // Unattended (default) mode: no manual-mode drop-in.
        assert!(!paths.dropin_file.exists());

        // The transcript hands over the three WooCommerce values and, since the
        // seed was pasted (not generated), does NOT reprint a fresh seed banner.
        assert!(transcript.contains("GoblinPay URL:   https://pay.myshop.com"));
        assert!(transcript.contains("API Token:       gp_live_"));
        assert!(transcript.contains("Webhook Secret:  whsec_"));
        assert!(transcript.contains("Using your existing seed"));
        assert!(transcript.contains("Restart mode: UNATTENDED"));
        assert!(!transcript.contains("WRITE THIS DOWN"));
    }

    #[test]
    fn fresh_seed_default_shows_the_seed_once() {
        let dir = TempDir::new("fresh");
        let opts = opts_with(&dir.0);
        // bind (Enter), password (twice), empty seed line -> generate fresh,
        // acknowledge, Enter for restart (unattended) + currencies + rail.
        let answers = "https://pay.myshop.com\nhttps://myshop.com\n\npw\npw\n\nyes\n\n\n\n";
        let mut out = Vec::new();
        run(Cursor::new(answers), &mut out, &opts).unwrap();
        let transcript = String::from_utf8(out).unwrap();
        // The fresh seed is shown once, with the acknowledgement gate.
        assert!(transcript.contains("WRITE THIS DOWN"));
        assert!(transcript.contains("Have you written down these 24 words?"));
        let paths = Paths::resolve(Some(&dir.0));
        assert!(GpWallet::seed_path(&paths.data_dir).exists());
        // Default currency applied; unattended is the default restart mode.
        assert!(fs::read_to_string(&paths.env_file)
            .unwrap()
            .contains("GP_RATE_CURRENCIES=usd"));
        assert!(transcript.contains("Restart mode: UNATTENDED"));
    }

    #[test]
    fn encrypted_unattended_seals_and_writes_no_plaintext() {
        let dir = TempDir::new("encrypted");
        let mut opts = opts_with(&dir.0);
        opts.seal = Some(fake_sealer_ok());
        // bind (Enter), password (twice), fresh seed, acknowledge, restart
        // (Enter = unattended), currencies, rail.
        let answers = "https://pay.myshop.com\nhttps://myshop.com\n\npw\npw\n\nyes\n\n\n\n";
        let mut out = Vec::new();
        run(Cursor::new(answers), &mut out, &opts).unwrap();
        let transcript = String::from_utf8(out).unwrap();
        let paths = Paths::resolve(Some(&dir.0));

        // The sealed ciphertext credential + the encrypted.conf drop-in exist;
        // NO plaintext password file and NO manual drop-in.
        assert!(paths.encrypted_cred_file.exists());
        assert!(paths.encrypted_dropin_file.exists());
        assert!(
            !paths.wallet_password_file.exists(),
            "no plaintext password on disk"
        );
        assert!(!paths.dropin_file.exists());
        // The sealed file never contains the plaintext password.
        let cred = fs::read_to_string(&paths.encrypted_cred_file).unwrap();
        assert!(!cred.contains("pw") || cred.contains("(sealed"));

        let dropin = fs::read_to_string(&paths.encrypted_dropin_file).unwrap();
        assert!(dropin.contains("LoadCredentialEncrypted=gp_wallet_password:"));
        assert!(dropin.contains("LoadCredential=\n")); // resets the plaintext one

        // Env points GP_WALLET_PASSWORD_FILE at the runtime credential path and
        // never inlines the password; the narrative says encrypted-at-rest.
        let env = fs::read_to_string(&paths.env_file).unwrap();
        assert!(env.contains(&format!(
            "GP_WALLET_PASSWORD_FILE={}",
            core_setup::CREDENTIALS_WALLET_PASSWORD_PATH
        )));
        assert!(!env.contains("GP_WALLET_PASSWORD="));
        assert!(env.contains("ENCRYPTED at rest"));
        assert!(GpWallet::seed_path(&paths.data_dir).exists());
        assert!(transcript.contains("Restart mode: UNATTENDED (encrypted at rest)"));
    }

    #[test]
    fn reconfigure_encrypted_till_prompts_for_the_password() {
        let dir = TempDir::new("recfg-enc");
        let mut opts = opts_with(&dir.0);
        opts.seal = Some(fake_sealer_ok());
        // Fresh encrypted till, password "pw".
        let answers = "https://pay.myshop.com\nhttps://myshop.com\n\npw\npw\n\nyes\n\n\n\n";
        let mut out = Vec::new();
        run(Cursor::new(answers), &mut out, &opts).unwrap();
        let paths = Paths::resolve(Some(&dir.0));
        assert!(
            !paths.wallet_password_file.exists(),
            "encrypted: no plaintext"
        );

        // Reconfigure: there is no readable password on disk, so the wizard must
        // prompt for it. Supplying the right password reopens the wallet.
        let mut recfg = opts_with(&dir.0);
        recfg.reconfigure = true;
        recfg.seal = Some(fake_sealer_ok());
        // public, webhook, bind (Enter), restart (Enter = preserve), currencies
        // gbp, rail n, then the EXISTING password prompt (pw) at wallet reopen.
        let recfg_answers = "https://pay.myshop.com\nhttps://myshop.com\n\n\ngbp\nn\npw\n";
        let mut out2 = Vec::new();
        run(Cursor::new(recfg_answers), &mut out2, &recfg).unwrap();
        let transcript = String::from_utf8(out2).unwrap();
        assert!(transcript.contains("keeps no readable password on disk"));
        assert!(transcript.contains("Reopening the existing till wallet"));
        let env = fs::read_to_string(&paths.env_file).unwrap();
        assert!(env.contains("GP_RATE_CURRENCIES=gbp"));
        assert!(env.contains("ENCRYPTED at rest"));
    }

    #[test]
    fn manual_mode_writes_dropin_and_no_password_file() {
        let dir = TempDir::new("manual");
        let opts = opts_with(&dir.0);
        // bind (Enter), fresh seed, acknowledge, restart mode 2 (manual),
        // defaults after.
        let answers = "https://pay.myshop.com\nhttps://myshop.com\n\npw\npw\n\nyes\n2\n\n\n";
        let mut out = Vec::new();
        run(Cursor::new(answers), &mut out, &opts).unwrap();
        let transcript = String::from_utf8(out).unwrap();
        let paths = Paths::resolve(Some(&dir.0));

        // Manual mode persists NO wallet password on disk, but writes the
        // tmpfs-credential drop-in (mode 0644).
        assert!(!paths.wallet_password_file.exists());
        assert!(paths.dropin_file.exists());
        let dropin_mode = fs::metadata(&paths.dropin_file)
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(dropin_mode, 0o644);
        let dropin = fs::read_to_string(&paths.dropin_file).unwrap();
        assert!(dropin.contains("LoadCredential=gp_wallet_password:"));
        assert!(dropin.contains("wallet_password"));

        // The wallet was still created (with the chosen password) and the env
        // points GP_WALLET_PASSWORD_FILE at the tmpfs runtime path.
        assert!(GpWallet::seed_path(&paths.data_dir).exists());
        let env = fs::read_to_string(&paths.env_file).unwrap();
        assert!(env.contains("MANUAL"));
        assert!(env.contains("run/goblinpay/wallet_password"));
        assert!(transcript.contains("Restart mode: MANUAL"));
        assert!(transcript.contains("systemd-ask-password"));
    }

    #[test]
    fn password_mismatch_reprompts_then_succeeds() {
        let dir = TempDir::new("mismatch");
        let opts = opts_with(&dir.0);
        // bind (Enter), first password pair mismatches (a/b), then a matching
        // pair (c/c) succeeds.
        let answers = "https://pay.myshop.com\nhttps://myshop.com\n\na\nb\nc\nc\n\nyes\n\n\n\n";
        let mut out = Vec::new();
        run(Cursor::new(answers), &mut out, &opts).unwrap();
        let transcript = String::from_utf8(out).unwrap();
        assert!(transcript.contains("passwords do not match"));
        let paths = Paths::resolve(Some(&dir.0));
        assert_eq!(
            fs::read_to_string(&paths.wallet_password_file)
                .unwrap()
                .trim_end(),
            "c"
        );
    }

    #[test]
    fn refuses_to_clobber_without_reconfigure() {
        let dir = TempDir::new("clobber");
        let opts = opts_with(&dir.0);
        let answers = format!(
            "https://pay.myshop.com\nhttps://myshop.com\n\n\
             pw\npw\n{DEV_SEED_24}\nyes\n\nusd\nn\n"
        );
        let mut out = Vec::new();
        run(Cursor::new(answers.clone()), &mut out, &opts).unwrap();
        // Second run without --reconfigure must refuse.
        let mut out2 = Vec::new();
        let err = run(Cursor::new(answers), &mut out2, &opts).unwrap_err();
        assert!(err.contains("already exists"), "got {err}");
        // With --reconfigure it proceeds, reusing the existing wallet+password
        // (no seed prompt) and rewriting the config. New tokens are generated.
        let paths = Paths::resolve(Some(&dir.0));
        let token_before = fs::read_to_string(&paths.env_file).unwrap();
        let mut recfg = opts_with(&dir.0);
        recfg.reconfigure = true;
        // Existing wallet => the seed/password questions are skipped, but bind,
        // restart mode (Enter = preserve current), currencies, and rail are asked.
        let recfg_answers = "https://pay.myshop.com\nhttps://myshop.com\n\n\ngbp\nn\n";
        let mut out3 = Vec::new();
        run(Cursor::new(recfg_answers), &mut out3, &recfg).unwrap();
        let transcript = String::from_utf8(out3).unwrap();
        assert!(transcript.contains("Existing till wallet found"));
        // Preserved the unattended mode it was set up with (Enter kept it).
        assert!(transcript.contains("Restart mode: UNATTENDED"));
        let token_after = fs::read_to_string(&paths.env_file).unwrap();
        assert!(token_after.contains("GP_RATE_CURRENCIES=gbp"));
        assert_ne!(token_before, token_after, "reconfigure regenerates config");
    }

    #[test]
    fn reconfigure_can_switch_restart_mode() {
        // The wart being fixed: reconfigure hardcoded UNATTENDED, so it silently
        // rewrote (and could never change) the restart mode. Now the operator is
        // prompted with the current mode as the default, so they can switch. An
        // unattended till HAS its password on the 0400 file, so it can reopen and
        // move that password off disk into manual mode.
        let dir = TempDir::new("recfg-switch");
        let opts = opts_with(&dir.0);
        // Fresh UNATTENDED till (Enter on the restart prompt).
        let answers = "https://pay.myshop.com\nhttps://myshop.com\n\npw\npw\n\nyes\n\n\n\n";
        let mut out = Vec::new();
        run(Cursor::new(answers), &mut out, &opts).unwrap();
        let paths = Paths::resolve(Some(&dir.0));
        assert!(paths.wallet_password_file.exists());
        assert!(!paths.dropin_file.exists());

        // Reconfigure and answer 2 (manual): it must switch, writing the drop-in
        // and taking the password off disk.
        let mut recfg = opts_with(&dir.0);
        recfg.reconfigure = true;
        let recfg_answers = "https://pay.myshop.com\nhttps://myshop.com\n\n2\ngbp\nn\n";
        let mut out2 = Vec::new();
        run(Cursor::new(recfg_answers), &mut out2, &recfg).unwrap();
        let transcript = String::from_utf8(out2).unwrap();
        assert!(transcript.contains("Restart mode: MANUAL"));
        assert!(paths.dropin_file.exists());
        assert!(
            !paths.wallet_password_file.exists(),
            "password moved off disk"
        );
        let env = fs::read_to_string(&paths.env_file).unwrap();
        assert!(env.contains("MANUAL"));
        assert!(env.contains("run/goblinpay/wallet_password"));
    }

    #[test]
    fn node_prompt_accepts_an_explicit_url() {
        let dir = TempDir::new("node");
        // No --node override, so the node question is asked; the operator names
        // their own node instead of pressing Enter (which would probe the net).
        let mut opts = opts_with(&dir.0);
        opts.node_override = None;
        let answers = "https://pay.myshop.com\nhttps://myshop.com\n\n\
             http://127.0.0.1:3413\npw\npw\n\nyes\n\n\n\n";
        let mut out = Vec::new();
        run(Cursor::new(answers), &mut out, &opts).unwrap();
        let paths = Paths::resolve(Some(&dir.0));
        let env = fs::read_to_string(&paths.env_file).unwrap();
        assert!(env.contains("GP_NODE_URL=http://127.0.0.1:3413"));
    }

    #[test]
    fn needs_first_run_setup_only_on_a_fresh_box() {
        let dir = TempDir::new("firstrun");
        let data_dir = dir.0.join("gp-data");
        let base = Config {
            data_dir: data_dir.display().to_string(),
            ..Config::default()
        };

        // Genuinely fresh: ingest on, no secrets, no seed, no env file.
        assert!(needs_first_run_setup(&base, false));

        // An env file already present means an operator configured this box: the
        // headless boot path must be taken (wizard never triggers).
        assert!(!needs_first_run_setup(&base, true));

        // A wallet password (or mnemonic) in the environment is a configured
        // deploy; boot headless.
        let with_pw = Config {
            wallet_password: Some(gp_core::config::Secret::new("pw".into())),
            ..Config {
                data_dir: data_dir.display().to_string(),
                ..Config::default()
            }
        };
        assert!(!needs_first_run_setup(&with_pw, false));

        // Ingest disabled: HTTP-only, no wallet needed, so do not force setup.
        let no_ingest = Config {
            ingest: false,
            ..Config {
                data_dir: data_dir.display().to_string(),
                ..Config::default()
            }
        };
        assert!(!needs_first_run_setup(&no_ingest, false));

        // An existing seed at rest is a configured wallet: boot headless.
        let seed_path = GpWallet::seed_path(&data_dir);
        if let Some(parent) = seed_path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(&seed_path, b"encrypted-seed").unwrap();
        assert!(!needs_first_run_setup(&base, false));
    }

    #[test]
    fn config_from_written_env_round_trips_the_wizard_output() {
        let dir = TempDir::new("written-env");
        let opts = opts_with(&dir.0);
        let answers = format!(
            "https://pay.myshop.com\nhttps://myshop.com\n\n\
             walletpass1\nwalletpass1\n{DEV_SEED_24}\nyes\n\nusd,eur\nn\n"
        );
        let mut out = Vec::new();
        run(Cursor::new(answers), &mut out, &opts).unwrap();

        // The env file the wizard wrote loads back into a Config the server can
        // boot from: an UNATTENDED run resolves the 0400 wallet-password file.
        let paths = Paths::resolve(Some(&dir.0));
        let cfg = config_from_written_env(&paths.env_file).unwrap();
        assert_eq!(cfg.public_url, "https://pay.myshop.com");
        assert_eq!(cfg.node_url, "http://127.0.0.1:3413");
        assert_eq!(cfg.relay_mode, gp_core::config::RelayMode::External);
        assert_eq!(cfg.rate_currencies, vec!["usd", "eur"]);
        assert!(
            cfg.wallet_password.is_some(),
            "the 0400 password file is resolved via GP_WALLET_PASSWORD_FILE"
        );
    }

    #[test]
    fn non_tty_without_batch_prints_guidance_and_errs() {
        let dir = TempDir::new("tty");
        let mut opts = opts_with(&dir.0);
        opts.force_run = false;
        opts.stdin_is_tty = false;
        let mut out = Vec::new();
        let err = run(Cursor::new(""), &mut out, &opts).unwrap_err();
        assert!(err.contains("TTY"), "got {err}");
        let printed = String::from_utf8(out).unwrap();
        assert!(printed.contains("interactive"));
        assert!(printed.contains("--batch"));
    }
}
