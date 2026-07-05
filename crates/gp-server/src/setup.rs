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

use gp_core::config::Chain;
use gp_core::setup as core_setup;
use gp_core::setup::SetupParams;
use gp_wallet::GpWallet;

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
    wallet_password_file: PathBuf,
    data_dir: PathBuf,
    db_path: PathBuf,
    /// The MANUAL-mode systemd drop-in (`gp-server.service.d/manual.conf`).
    dropin_file: PathBuf,
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
        Paths {
            env_file: join("etc/goblinpay.env"),
            wallet_password_file: secrets_dir.join("wallet_password"),
            secrets_dir,
            data_dir: join("var/lib/goblinpay/gp-data"),
            db_path: join("var/lib/goblinpay/goblinpay.db"),
            dropin_file: join("etc/systemd/system/gp-server.service.d/manual.conf"),
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

    // Hidden password entry only when stdin is a real terminal; scripted/batch
    // runs (and tests) read the password as plain lines from `input`.
    let hidden = opts.stdin_is_tty;

    // Q3–Q5 concern the wallet secrets and the restart mode, and are only asked
    // for a NEW wallet. On a --reconfigure with an existing wallet we keep the
    // seed, password, and restart arrangement at rest untouched (that is the
    // money), so prompting for any of them would be a trap.
    let wallet_exists = seed_path.exists();
    let (seed_plan, chosen_password, restart_mode) = if wallet_exists {
        writeln!(
            out,
            "Existing till wallet found; keeping its seed, password, and restart \
             mode unchanged."
        )
        .map_err(io_err)?;
        (
            SeedPlan::Existing,
            None,
            core_setup::RestartMode::Unattended,
        )
    } else {
        // Q3: the operator CHOOSES the wallet password (grin-wallet-faithful:
        // entered twice, must match). It encrypts the seed at rest.
        let password = prompt_wallet_password(&mut input, out, hidden)?;

        // Q4: the seed. Fresh (generate, show ONCE, acknowledge) or paste an
        // existing recovery phrase (acknowledge the written backup). Both paths
        // are gated behind an explicit acknowledgement, like grin-wallet init.
        writeln!(
            out,
            "4) Grin seed: press Enter to generate a FRESH 24-word till seed,\n\
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

        // Q5: restart mode (owner ruling: offer both, default UNATTENDED).
        writeln!(
            out,
            "5) After a reboot, how should the till restart?\n\
             \x20  [1] Unattended (default) — your password is sealed to THIS host, so\n\
             \x20      the service auto-restarts. Honest trade-off: whoever fully\n\
             \x20      controls this machine controls the wallet; keep it a small hot\n\
             \x20      float and sweep to your own wallet regularly.\n\
             \x20  [2] Manual — the password lives only in your head; you re-enter it\n\
             \x20      after every restart. Maximum protection against disk/machine theft."
        )
        .map_err(io_err)?;
        write!(out, "   > [1] ").map_err(io_err)?;
        out.flush().map_err(io_err)?;
        let mode = core_setup::parse_restart_mode(&read_line(&mut input)?);

        (plan, Some(password), mode)
    };

    // Q6: currencies (default usd).
    writeln!(out, "6) Currencies your shop prices in? [usd]").map_err(io_err)?;
    write!(out, "   > ").map_err(io_err)?;
    out.flush().map_err(io_err)?;
    let currencies = core_setup::parse_currencies(&read_line(&mut input)?);

    // Q7: advanced grin1/Tor rail (default no).
    writeln!(
        out,
        "7) (advanced) Also accept payments from any Grin wallet over Tor? [y/N]"
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

    // Pick a healthy Grin node: an explicit override, else probe the curated
    // list and take the first that answers.
    writeln!(out).map_err(io_err)?;
    let node_url = match &opts.node_override {
        Some(url) => {
            writeln!(out, "Using Grin node {url} (override).").map_err(io_err)?;
            url.clone()
        }
        None => {
            writeln!(out, "Probing curated Grin nodes for a healthy one...").map_err(io_err)?;
            let chosen = core_setup::select_node(core_setup::CURATED_NODES, gp_wallet::probe_node);
            match chosen {
                Some(url) => {
                    writeln!(out, "Using Grin node {url}.").map_err(io_err)?;
                    url
                }
                None => {
                    return Err(
                        "none of the curated Grin nodes answered. Check this host's \
                         network, or pass --node <url> to use a node you trust."
                            .into(),
                    )
                }
            }
        }
    };

    // Create (or, on reconfigure, reopen) the encrypted wallet. Creating
    // consumes the seed once: it lives encrypted at rest afterwards, never in
    // the service environment (owner ruling O2). Reopening an existing wallet
    // reuses the password already on file, so a --reconfigure never re-encrypts
    // (which would need the old password) or touches the seed.
    ensure_dir(&paths.data_dir, 0o700)?;
    ensure_dir(&paths.secrets_dir, 0o700)?;
    let wallet = match &seed_plan {
        SeedPlan::Existing => {
            let password = fs::read_to_string(&paths.wallet_password_file)
                .map_err(|e| {
                    format!(
                        "existing wallet found but its password file {} is unreadable ({e}); \
                         cannot reopen. This looks like a partial install, not a reconfigure.",
                        paths.wallet_password_file.display()
                    )
                })?
                .trim_end_matches(['\n', '\r'])
                .to_string();
            writeln!(out, "Reopening the existing till wallet...").map_err(io_err)?;
            GpWallet::create_at(&paths.data_dir, None, &password, &node_url, Chain::Mainnet)
                .map_err(|e| format!("could not reopen the existing wallet: {e}"))?
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
            // Persist per restart mode. UNATTENDED seals the chosen password to
            // this host as a 0400 credential file (systemd LoadCredential reads
            // it, so the service auto-restarts). MANUAL persists NOTHING: it
            // writes only the drop-in that repoints the credential to a tmpfs
            // path the operator populates by hand at each start.
            match restart_mode {
                core_setup::RestartMode::Unattended => {
                    write_secret_file(&paths.wallet_password_file, password)?;
                }
                core_setup::RestartMode::Manual => {
                    let runtime_pw = paths.runtime_password_file.display().to_string();
                    write_dropin_file(
                        &paths.dropin_file,
                        &core_setup::render_manual_dropin(&runtime_pw),
                    )?;
                }
            }
            w
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
        core_setup::RestartMode::Unattended => paths.wallet_password_file.display().to_string(),
        core_setup::RestartMode::Manual => paths.runtime_password_file.display().to_string(),
    };

    // Render + write the env file (0640) the service loads.
    let params = SetupParams {
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
        core_setup::RestartMode::Unattended => writeln!(
            out,
            "Restart mode: UNATTENDED. Start it:  sudo systemctl start gp-server\n\
             It will auto-restart after reboots using the host-sealed password.\n\
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
        core_setup::RestartMode::Unattended => writeln!(
            out,
            "\nWrote {} and {} (password file, mode 0400).",
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

/// Create a directory (and parents) with the given mode.
fn ensure_dir(path: &Path, mode: u32) -> Result<(), String> {
    fs::create_dir_all(path).map_err(|e| format!("cannot create {}: {e}", path.display()))?;
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
        .map_err(|e| format!("cannot chmod {}: {e}", path.display()))
}

/// Write a secret to `path` with mode 0400 (create-or-truncate, then chmod).
fn write_secret_file(path: &Path, contents: &str) -> Result<(), String> {
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
        }
    }

    /// All-zero 32-byte entropy -> the well-known dev seed (24 words). Used only
    /// as a test fixture; never a real till seed.
    const DEV_SEED_24: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";

    #[test]
    fn full_run_writes_files_with_modes_and_paste_block() {
        let dir = TempDir::new("full");
        let opts = opts_with(&dir.0);
        // Answers: public url, shop url, chosen password (twice), paste the dev
        // seed, acknowledge, restart mode (Enter = unattended), currencies, rail.
        let answers = format!(
            "https://pay.myshop.com\nhttps://myshop.com\n\
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
        // password (twice), empty seed line -> generate fresh, acknowledge,
        // Enter for restart (unattended) + currencies + rail.
        let answers = "https://pay.myshop.com\nhttps://myshop.com\npw\npw\n\nyes\n\n\n\n";
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
    fn manual_mode_writes_dropin_and_no_password_file() {
        let dir = TempDir::new("manual");
        let opts = opts_with(&dir.0);
        // Fresh seed, acknowledge, restart mode 2 (manual), defaults after.
        let answers = "https://pay.myshop.com\nhttps://myshop.com\npw\npw\n\nyes\n2\n\n\n";
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
        // First pair mismatches (a/b), then a matching pair (c/c) succeeds.
        let answers = "https://pay.myshop.com\nhttps://myshop.com\na\nb\nc\nc\n\nyes\n\n\n\n";
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
            "https://pay.myshop.com\nhttps://myshop.com\n\
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
        // Existing wallet => the seed question is skipped; feed 4 answers.
        let recfg_answers = "https://pay.myshop.com\nhttps://myshop.com\ngbp\nn\n";
        let mut out3 = Vec::new();
        run(Cursor::new(recfg_answers), &mut out3, &recfg).unwrap();
        let transcript = String::from_utf8(out3).unwrap();
        assert!(transcript.contains("Existing till wallet found"));
        let token_after = fs::read_to_string(&paths.env_file).unwrap();
        assert!(token_after.contains("GP_RATE_CURRENCIES=gbp"));
        assert_ne!(token_before, token_after, "reconfigure regenerates config");
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
