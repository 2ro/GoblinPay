//! The `gp-server setup` interactive onboarding wizard.
//!
//! This is the guided, secure path to standing up a till: it asks a handful of
//! questions (all with defaults), generates every secret itself, creates the
//! encrypted wallet on the spot, probes a curated node list for a healthy one,
//! writes the env + credential files exactly where the shipped systemd unit
//! looks, and prints the three values to paste into WooCommerce. The operator
//! never invents a token, edits a config file, or types a password.
//!
//! The pure parts (secret generation, answer parsing, node selection, the two
//! rendered outputs) live in `gp_core::setup` and are unit-tested there. This
//! module is the impure shell: the prompt loop, the real network probe, wallet
//! creation, and file writing. It is driven over generic reader/writer handles
//! so the flow can be exercised against a `Cursor` + temp dir in tests.

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
        }
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
        "Answer a few questions; everything else is chosen and generated for you.\n"
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

    // Q3: seed. Only asked when there is no wallet yet. On a --reconfigure with
    // an existing wallet we keep the seed at rest untouched (it is the money and
    // its password is already generated), so asking for a seed would be a trap.
    let wallet_exists = seed_path.exists();
    let seed_plan = if wallet_exists {
        writeln!(
            out,
            "Existing till wallet found; keeping its seed and password unchanged."
        )
        .map_err(io_err)?;
        SeedPlan::Existing
    } else {
        writeln!(
            out,
            "3) Grin seed: press Enter to generate a FRESH till seed, or paste your \
             existing 24 words."
        )
        .map_err(io_err)?;
        write!(out, "   > ").map_err(io_err)?;
        out.flush().map_err(io_err)?;
        let seed_line = read_line(&mut input)?;
        if seed_line.trim().is_empty() {
            let entropy = core_setup::gen_entropy_32();
            let m = gp_wallet::mnemonic_from_entropy(&entropy)
                .map_err(|e| format!("could not generate a seed: {e}"))?;
            SeedPlan::Fresh(m)
        } else {
            SeedPlan::Pasted(seed_line.trim().to_string())
        }
    };

    // Q4: currencies (default usd).
    writeln!(out, "4) Currencies your shop prices in? [usd]").map_err(io_err)?;
    write!(out, "   > ").map_err(io_err)?;
    out.flush().map_err(io_err)?;
    let currencies = core_setup::parse_currencies(&read_line(&mut input)?);

    // Q5: advanced grin1/Tor rail (default no).
    writeln!(
        out,
        "5) (advanced) Also accept payments from any Grin wallet over Tor? [y/N]"
    )
    .map_err(io_err)?;
    write!(out, "   > ").map_err(io_err)?;
    out.flush().map_err(io_err)?;
    let grin1_rail = core_setup::parse_yes_no(&read_line(&mut input)?, false);

    // Generate the bearer secrets (the operator never types or invents these).
    // The wallet password is generated only for a NEW wallet; an existing one
    // keeps the password already on file (it is the only thing that can decrypt
    // the seed at rest).
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
            let password = core_setup::gen_wallet_password();
            writeln!(out, "Creating the encrypted till wallet...").map_err(io_err)?;
            let w = GpWallet::create_at(
                &paths.data_dir,
                Some(m),
                &password,
                &node_url,
                Chain::Mainnet,
            )
            .map_err(|e| format!("wallet creation failed: {e}"))?;
            // Write the wallet-password credential file (0400) where the unit's
            // LoadCredential reads it.
            write_secret_file(&paths.wallet_password_file, &password)?;
            w
        }
    };
    match wallet.slatepack_address() {
        Ok(addr) => writeln!(out, "Wallet ready (address {addr}).").map_err(io_err)?,
        Err(e) => return Err(format!("wallet opened but address read failed: {e}")),
    }

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
        wallet_password_file: paths.wallet_password_file.display().to_string(),
    };
    write_env_file(&paths.env_file, &params.render_env())?;

    // If we generated the seed, show it ONCE with a write-it-down warning: this
    // is the operator's only backup of the money.
    writeln!(out).map_err(io_err)?;
    match &seed_plan {
        SeedPlan::Fresh(mnemonic) => writeln!(
            out,
            "============================================================\n\
             WRITE THIS DOWN. This is your till's seed, its money backup.\n\
             It is shown ONCE and never again. Store it offline, safely.\n\
             ------------------------------------------------------------\n\
             {mnemonic}\n\
             ============================================================\n"
        )
        .map_err(io_err)?,
        SeedPlan::Pasted(_) => writeln!(
            out,
            "Using your existing seed. Keep your written backup of it safe.\n"
        )
        .map_err(io_err)?,
        SeedPlan::Existing => writeln!(
            out,
            "Kept the existing till wallet; its seed and password are unchanged.\n"
        )
        .map_err(io_err)?,
    }

    // Final screen: how to start, and the copy-paste block for WooCommerce.
    writeln!(
        out,
        "GoblinPay is set up. Start it:  sudo systemctl start gp-server\n"
    )
    .map_err(io_err)?;
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

    writeln!(
        out,
        "\nWrote {} and {} (password file, mode 0400).",
        paths.env_file.display(),
        paths.wallet_password_file.display()
    )
    .map_err(io_err)?;

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
    let mut buf = String::new();
    let n = input.read_line(&mut buf).map_err(io_err)?;
    if n == 0 {
        return Ok(String::new());
    }
    Ok(buf.trim_end_matches(['\n', '\r']).to_string())
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
        // Answers: public url, shop url, paste the dev seed, currencies, no rail.
        let answers =
            format!("https://pay.myshop.com\nhttps://myshop.com\n{DEV_SEED_24}\nusd,eur\nn\n");
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

        // The wallet password file exists, mode 0400, non-empty.
        let pw_mode = fs::metadata(&paths.wallet_password_file)
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(pw_mode, 0o400);
        assert!(!fs::read_to_string(&paths.wallet_password_file)
            .unwrap()
            .trim()
            .is_empty());

        // The encrypted seed was created.
        assert!(GpWallet::seed_path(&paths.data_dir).exists());

        // The transcript hands over the three WooCommerce values and, since the
        // seed was pasted (not generated), does NOT reprint a fresh seed banner.
        assert!(transcript.contains("GoblinPay URL:   https://pay.myshop.com"));
        assert!(transcript.contains("API Token:       gp_live_"));
        assert!(transcript.contains("Webhook Secret:  whsec_"));
        assert!(transcript.contains("Using your existing seed"));
        assert!(!transcript.contains("WRITE THIS DOWN"));
    }

    #[test]
    fn fresh_seed_default_shows_the_seed_once() {
        let dir = TempDir::new("fresh");
        let opts = opts_with(&dir.0);
        // Empty seed line -> generate fresh. Enter for currencies + rail too.
        let answers = "https://pay.myshop.com\nhttps://myshop.com\n\n\n\n";
        let mut out = Vec::new();
        run(Cursor::new(answers), &mut out, &opts).unwrap();
        let transcript = String::from_utf8(out).unwrap();
        assert!(transcript.contains("WRITE THIS DOWN"));
        // 24 space-separated words are shown.
        let paths = Paths::resolve(Some(&dir.0));
        assert!(GpWallet::seed_path(&paths.data_dir).exists());
        // Default currency applied.
        assert!(fs::read_to_string(&paths.env_file)
            .unwrap()
            .contains("GP_RATE_CURRENCIES=usd"));
    }

    #[test]
    fn refuses_to_clobber_without_reconfigure() {
        let dir = TempDir::new("clobber");
        let opts = opts_with(&dir.0);
        let answers =
            format!("https://pay.myshop.com\nhttps://myshop.com\n{DEV_SEED_24}\nusd\nn\n");
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
