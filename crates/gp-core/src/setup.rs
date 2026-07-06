//! Pure building blocks for the `gp-server setup` onboarding wizard.
//!
//! Everything here is deterministic-shaped and side-effect free (except the
//! CSPRNG token/entropy generators, which take no input): answer normalization,
//! secret generation, the curated node list, healthy-node selection over a
//! caller-supplied probe, and the two rendered outputs the wizard writes and
//! prints (the `goblinpay.env` file and the WooCommerce paste block). The
//! interactive prompt loop, the real network probe, wallet creation, and file
//! writing live in `gp-server` (they need a TTY, the node client, the wallet
//! stack, and the filesystem); this module holds the parts that are worth
//! unit-testing without any of that.
//!
//! Owner rulings baked in here:
//! - relays default to an EXTERNAL vetted pool (the wallet's proven relays), not
//!   a per-till bundled relay (O5);
//! - the Grin node defaults to a curated healthy mainnet node, health-probed at
//!   setup with fallback to the next candidate (O5/node);
//! - bearer tokens live in the root-owned env file for v1 (O4);
//! - the wallet password is chosen by the OPERATOR (grin-wallet-faithful:
//!   entered twice and confirmed to match), never auto-generated; the service
//!   secrets (API token, admin token, webhook secret) are still generated for
//!   you. `GP_MNEMONIC` is never written to the env (O2); the seed exists only
//!   encrypted at rest and in the operator's written backup.
//! - two restart modes are offered, defaulting to UNATTENDED: the chosen
//!   password is host-sealed via a systemd credential so the service
//!   auto-restarts; or MANUAL, where nothing is persisted and the operator
//!   re-enters the password after every restart.

use rand::RngCore;

use crate::config::DEFAULT_BIND;

/// Curated known-good mainnet Grin nodes, in preference order. Every entry was
/// verified to answer `get_tip` on its `/v2/foreign` endpoint at build time
/// (2026-07-05, all three reporting the same tip height). GoblinPay only ever
/// reads the node (`get_tip`, `get_kernel`), so an endpoint that serves the
/// foreign API is sufficient even if its bulk UTXO scan is unreliable. The
/// wizard probes these in order and picks the first that answers, so a
/// temporarily-down leader falls back to the next automatically.
pub const CURATED_NODES: &[&str] = &[
    // The shipped production default (also the source of the recorded fixture in
    // gp-wallet's confirmation tests); serves the foreign API cleanly.
    "https://main.gri.mw",
    // Long-standing public node; serves get_tip/get_kernel.
    "https://api.grin.money",
    // Community public node; verified answering at the same tip.
    "https://grincoin.org",
];

/// Default EXTERNAL relay pool for the easy path (owner ruling O5): the wallet's
/// proven, gift-wrap-friendly, Tor-exit-friendly relays. The operator can swap
/// these; running one's own relay is advanced/opt-in and not the default.
pub const DEFAULT_RELAYS: &[&str] = &["wss://relay.floonet.dev", "wss://offchain.pub"];

/// Default fiat currency the wizard proposes (matches the server default).
pub const DEFAULT_CURRENCY: &str = "usd";

/// The path, relative to a shop's site root, WooCommerce serves the GoblinPay
/// webhook receiver at. The wizard turns the operator's shop URL into the full
/// `GP_WEBHOOK_URL` by appending this.
pub const WEBHOOK_PATH: &str = "/wp-json/goblinpay/v1/webhook";

/// Where the shipped `gp-server.service` reads its `EnvironmentFile` from, and
/// where the wizard writes the rendered config. Used both as the wizard's
/// output path and as the "already configured" signal on a bare `gp-server`
/// first run (its presence means an operator has set this instance up already).
pub const DEFAULT_ENV_FILE: &str = "/etc/goblinpay.env";

/// Fill `buf` with cryptographically-secure random bytes (the OS CSPRNG).
pub fn fill_random(buf: &mut [u8]) {
    rand::rng().fill_bytes(buf);
}

/// 32 bytes of CSPRNG entropy, for BIP-39 mnemonic generation (24 words). The
/// wizard hands this to `gp_wallet::mnemonic_from_entropy`; kept here so the one
/// randomness dependency (rand) stays in gp-core and out of the wallet crate.
pub fn gen_entropy_32() -> [u8; 32] {
    let mut e = [0u8; 32];
    fill_random(&mut e);
    e
}

/// Lowercase hex of `bytes` random bytes.
fn random_hex(bytes: usize) -> String {
    let mut b = vec![0u8; bytes];
    fill_random(&mut b);
    let mut s = String::with_capacity(bytes * 2);
    for byte in b {
        s.push_str(&format!("{byte:02x}"));
    }
    s
}

/// A generated secret with a stable, recognizable prefix. 16 random bytes (128
/// bits) rendered as 32 hex chars follow the prefix.
fn prefixed_secret(prefix: &str) -> String {
    format!("{prefix}{}", random_hex(16))
}

/// Connector/create-invoice bearer token (`GP_API_TOKEN`). Shape: `gp_live_<32 hex>`.
pub fn gen_api_token() -> String {
    prefixed_secret("gp_live_")
}

/// Admin dashboard/API bearer token (`GP_ADMIN_TOKEN`). Shape: `gpadm_<32 hex>`.
pub fn gen_admin_token() -> String {
    prefixed_secret("gpadm_")
}

/// Webhook HMAC secret (`GP_WEBHOOK_SECRET`). Shape: `whsec_<32 hex>`.
pub fn gen_webhook_secret() -> String {
    prefixed_secret("whsec_")
}

/// Validate an operator-chosen wallet password. grin-wallet-faithful: the
/// operator picks their own password (it encrypts the seed at rest), so the
/// only hard rule is that it must not be empty. Returns the reason on rejection.
pub fn validate_password(pw: &str) -> Result<(), String> {
    if pw.is_empty() {
        return Err("password must not be empty".into());
    }
    Ok(())
}

/// Whether two password entries match exactly. The wizard prompts twice and
/// only proceeds when this is true (grin-wallet's confirm-to-match behaviour).
pub fn passwords_match(first: &str, second: &str) -> bool {
    first == second
}

/// How the till restarts after a reboot (the operator's choice; owner ruling:
/// offer both, default UNATTENDED).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RestartMode {
    /// The chosen password is sealed to this host via a systemd credential, so
    /// the service auto-restarts without a human. A full-machine compromise
    /// means wallet compromise; mitigate with a small hot-till float + sweeps.
    Unattended,
    /// The password lives only in the operator's head; it is re-entered after
    /// every restart (nothing sensitive on disk). Max protection against
    /// disk/machine theft, at the cost of hands-on restarts.
    Manual,
}

impl RestartMode {
    /// Lowercase identifier used in rendered comments/markers.
    pub fn as_str(self) -> &'static str {
        match self {
            RestartMode::Unattended => "unattended",
            RestartMode::Manual => "manual",
        }
    }
}

/// Parse the restart-mode answer, falling back to `default` on an empty (Enter)
/// or unrecognized answer rather than trapping the operator. Accepts
/// `1`/`u`/`unattended` and `2`/`m`/`manual` (case-insensitive). Reconfigure
/// passes the till's CURRENT mode as the default so pressing Enter preserves it;
/// a fresh setup passes UNATTENDED.
pub fn parse_restart_mode_default(input: &str, default: RestartMode) -> RestartMode {
    match input.trim().to_lowercase().as_str() {
        "1" | "u" | "unattended" => RestartMode::Unattended,
        "2" | "m" | "manual" => RestartMode::Manual,
        _ => default,
    }
}

/// Parse the restart-mode answer with the fresh-setup default (UNATTENDED).
/// Pressing Enter (empty) or an unknown answer takes UNATTENDED.
pub fn parse_restart_mode(input: &str) -> RestartMode {
    parse_restart_mode_default(input, RestartMode::Unattended)
}

/// Parse a seed-acknowledgement answer. Unlike `parse_yes_no`, there is no
/// affirmative default: the operator must explicitly type `y`/`yes` to confirm
/// they wrote the seed down. Everything else (including Enter) is "not yet".
pub fn parse_ack(input: &str) -> bool {
    matches!(input.trim().to_lowercase().as_str(), "y" | "yes")
}

/// Path, relative to the systemd state layout, of the tmpfs credential the
/// MANUAL restart mode reads the wallet password from at each start. `/run` is
/// tmpfs, so the password is gone on reboot: a powered-off disk holds no key.
pub const RUNTIME_WALLET_PASSWORD_FILE: &str = "/run/goblinpay/wallet_password";

/// Render the systemd drop-in that switches the unit to MANUAL restart mode: it
/// repoints `LoadCredential` from the persistent 0400 file to the tmpfs path the
/// operator populates by hand at each start, and documents exactly how. Written
/// to `/etc/systemd/system/gp-server.service.d/manual.conf` by the wizard only
/// when the operator chooses manual restarts.
pub fn render_manual_dropin(runtime_password_file: &str) -> String {
    format!(
        "# GoblinPay MANUAL restart mode, generated by `gp-server setup`.\n\
         # The wallet password is NOT stored on disk. Re-enter it after every\n\
         # restart (and after every reboot), which populates a tmpfs credential:\n\
         #\n\
         #   sudo install -d -m0700 /run/goblinpay\n\
         #   systemd-ask-password \"GoblinPay wallet password:\" \\\n\
         #     | sudo install -m0400 /dev/stdin {rt}\n\
         #   sudo systemctl start gp-server\n\
         #\n\
         # /run is tmpfs, so the password vanishes on reboot: a stolen or\n\
         # powered-off disk holds no wallet key. The service will NOT come back\n\
         # on its own after a restart until you re-enter the password.\n\
         [Service]\n\
         # Reset the base unit's persistent credential, then read the tmpfs one.\n\
         LoadCredential=\n\
         LoadCredential=gp_wallet_password:{rt}\n",
        rt = runtime_password_file
    )
}

/// Normalize an operator-entered base URL: trim surrounding whitespace and any
/// trailing slashes, and require an explicit `http://` or `https://` scheme so
/// a bare host can never silently become a relative link. Returns the cleaned
/// URL or a human error naming what was wrong.
pub fn normalize_url(input: &str) -> Result<String, String> {
    let t = input.trim().trim_end_matches('/');
    if t.is_empty() {
        return Err("a URL is required".into());
    }
    if !t.starts_with("http://") && !t.starts_with("https://") {
        return Err(format!(
            "URL must start with http:// or https:// (got `{t}`)"
        ));
    }
    Ok(t.to_string())
}

/// Build the full webhook URL from a shop's site URL: normalize it, then append
/// the WooCommerce receiver path.
pub fn webhook_url_from_shop(shop: &str) -> Result<String, String> {
    Ok(format!("{}{WEBHOOK_PATH}", normalize_url(shop)?))
}

/// The path prefix a public URL mounts the app under, for building root-relative
/// links in the served pages. A bare host (subdomain or root) yields an empty
/// prefix (`https://pay.myshop.com` -> ``); a path yields it with no trailing
/// slash (`https://myshop.com/pay` -> `/pay`). This lets the operator host the
/// till on a reverse-proxied path of an existing domain with ZERO new DNS
/// records: the pages emit `{prefix}/static/...`, `{prefix}/pay/...`, etc., and
/// a prefix-stripping proxy maps them back to the app's root routes.
pub fn base_path(public_url: &str) -> String {
    // Strip the scheme, then take everything from the first `/` (the path).
    let after_scheme = public_url
        .split_once("://")
        .map(|(_, rest)| rest)
        .unwrap_or(public_url);
    match after_scheme.find('/') {
        Some(i) => after_scheme[i..].trim_end_matches('/').to_string(),
        None => String::new(),
    }
}

/// Normalize an operator-entered listen address: trim surrounding whitespace and
/// fall back to the loopback default (`127.0.0.1:8080`) on an empty answer, so
/// pressing Enter is a valid response. The address stays behind the reverse
/// proxy, so no scheme or validation beyond non-empty is imposed here (the
/// config layer rejects an empty bind).
pub fn normalize_bind(input: &str) -> String {
    let t = input.trim();
    if t.is_empty() {
        DEFAULT_BIND.to_string()
    } else {
        t.to_string()
    }
}

/// Parse a rendered env file (the wizard's own `render_env` output, or an
/// equivalent hand-written one) into `(KEY, VALUE)` pairs. Blank lines and
/// `#`-comment lines are skipped; each remaining line is split on the FIRST `=`,
/// with the key and value trimmed. This lets a bare `gp-server` first run boot
/// directly from the file the wizard just wrote, without shelling out to a
/// systemd `EnvironmentFile` reload.
pub fn parse_env_file(contents: &str) -> Vec<(String, String)> {
    let mut pairs = Vec::new();
    for line in contents.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some((key, value)) = line.split_once('=') {
            let key = key.trim().to_string();
            if !key.is_empty() {
                pairs.push((key, value.trim().to_string()));
            }
        }
    }
    pairs
}

/// Parse a comma-separated currency answer into lowercased ISO codes, dropping
/// blanks. An empty answer yields the default (`usd`), so pressing Enter is a
/// valid response.
pub fn parse_currencies(input: &str) -> Vec<String> {
    let list: Vec<String> = input
        .split(',')
        .map(|s| s.trim().to_lowercase())
        .filter(|s| !s.is_empty())
        .collect();
    if list.is_empty() {
        vec![DEFAULT_CURRENCY.to_string()]
    } else {
        list
    }
}

/// Parse a yes/no answer with a default for the empty (Enter) response.
/// Accepts `y`/`yes`/`n`/`no` (case-insensitive). Any other value returns the
/// default rather than erroring: the advanced toggle should never trap the
/// operator.
pub fn parse_yes_no(input: &str, default: bool) -> bool {
    match input.trim().to_lowercase().as_str() {
        "" => default,
        "y" | "yes" => true,
        "n" | "no" => false,
        _ => default,
    }
}

/// Select the first candidate node the `probe` reports healthy. Pure: the real
/// wizard passes a closure that does a `get_tip` round trip, tests pass a mock.
/// Returns `None` only if every candidate failed.
pub fn select_node<F: FnMut(&str) -> bool>(candidates: &[&str], mut probe: F) -> Option<String> {
    candidates
        .iter()
        .find(|url| probe(url))
        .map(|s| s.to_string())
}

/// The resolved answers plus generated secrets the wizard renders into the env
/// file and the paste block. Secrets are plain `String`s here (this is the one
/// place they must be written out); callers zeroize/scope them.
#[derive(Debug, Clone)]
pub struct SetupParams {
    /// Local listen address the server binds (`GP_BIND`); loopback by default,
    /// kept behind the operator's reverse proxy.
    pub bind: String,
    /// Public URL customers reach the till at (`GP_PUBLIC_URL`).
    pub public_url: String,
    /// Full webhook URL on the shop (`GP_WEBHOOK_URL`).
    pub webhook_url: String,
    /// Chosen healthy Grin node (`GP_NODE_URL`).
    pub node_url: String,
    /// External relay pool (`GP_RELAYS`, `GP_RELAY_MODE=external`).
    pub relays: Vec<String>,
    /// Fiat currencies (`GP_RATE_CURRENCIES`).
    pub currencies: Vec<String>,
    /// grin1/Tor rail toggle (`GP_GRIN1_RAIL`), default off.
    pub grin1_rail: bool,
    /// Connector API bearer token (`GP_API_TOKEN`).
    pub api_token: String,
    /// Admin bearer token (`GP_ADMIN_TOKEN`).
    pub admin_token: String,
    /// Webhook HMAC secret (`GP_WEBHOOK_SECRET`).
    pub webhook_secret: String,
    /// Absolute data dir the wallet + seed live under (`GP_DATA_DIR`).
    pub data_dir: String,
    /// Absolute SQLite DB path (`GP_DB_PATH`).
    pub db_path: String,
    /// Absolute path of the mounted wallet-password credential file
    /// (`GP_WALLET_PASSWORD_FILE`), as the service reads it at runtime. In
    /// UNATTENDED mode this is the persistent 0400 file the wizard writes; in
    /// MANUAL mode it is the tmpfs path the operator populates at each start.
    pub wallet_password_file: String,
    /// How the till restarts (operator's choice; default UNATTENDED).
    pub restart_mode: RestartMode,
}

impl SetupParams {
    /// Render the non-secret + bearer-token config file the service loads as its
    /// `EnvironmentFile` (owner ruling O4: tokens live in this root-owned file).
    /// The wallet password is referenced by file (never inlined) and the Grin
    /// seed is absent entirely (owner ruling O2: it exists only encrypted at
    /// rest and in the operator's written backup).
    pub fn render_env(&self) -> String {
        let mut s = String::new();
        s.push_str("# GoblinPay configuration, generated by `gp-server setup`.\n");
        s.push_str("# Non-secret config plus bearer tokens (root-owned, mode 0640).\n");
        s.push_str("# The wallet password is a separate 0400 credential file; the Grin\n");
        s.push_str(
            "# seed is NOT here (it lives encrypted at rest and in your written backup).\n\n",
        );

        s.push_str("# --- local listen address (loopback; keep it behind your proxy) ---\n");
        s.push_str(&format!("GP_BIND={}\n\n", self.bind));

        s.push_str("# --- public URL customers reach this till at ---\n");
        s.push_str(&format!("GP_PUBLIC_URL={}\n\n", self.public_url));

        s.push_str("# --- relays (external vetted pool; swap for your own if you like) ---\n");
        s.push_str("GP_RELAY_MODE=external\n");
        s.push_str(&format!("GP_RELAYS={}\n\n", self.relays.join(",")));

        s.push_str(
            "# --- Grin node (read-only: confirmations + balance), health-probed at setup ---\n",
        );
        s.push_str(&format!("GP_NODE_URL={}\n\n", self.node_url));

        s.push_str("# --- pricing ---\n");
        s.push_str(&format!(
            "GP_RATE_CURRENCIES={}\n",
            self.currencies.join(",")
        ));
        s.push_str("GP_MATCH_MODE=derived\n\n");

        s.push_str("# --- connector + admin bearer tokens (capabilities) ---\n");
        s.push_str(&format!("GP_API_TOKEN={}\n", self.api_token));
        s.push_str(&format!("GP_ADMIN_TOKEN={}\n\n", self.admin_token));

        s.push_str("# --- webhook to your shop (HMAC-signed) ---\n");
        s.push_str(&format!("GP_WEBHOOK_URL={}\n", self.webhook_url));
        s.push_str(&format!("GP_WEBHOOK_SECRET={}\n\n", self.webhook_secret));

        // Wallet password: operator-chosen (grin-wallet-faithful), never
        // inlined here. How it reaches the service depends on the restart mode.
        match self.restart_mode {
            RestartMode::Unattended => {
                s.push_str("# --- wallet password: restart mode UNATTENDED (host-sealed) ---\n");
                s.push_str(
                    "# You chose this password; it is sealed to THIS host as a systemd\n\
                     # credential (the 0400 file below), so the service auto-restarts with\n\
                     # no human. Honest trade-off: a full-machine compromise means wallet\n\
                     # compromise. Mitigate by keeping the till a small hot float and\n\
                     # sweeping to your own wallet regularly.\n",
                );
            }
            RestartMode::Manual => {
                s.push_str("# --- wallet password: restart mode MANUAL (nothing on disk) ---\n");
                s.push_str(
                    "# You chose this password; it is NOT stored on disk. You re-enter it\n\
                     # after every restart, into the tmpfs credential below (see the\n\
                     # gp-server.service.d/manual.conf drop-in). Max protection against\n\
                     # disk/machine theft; the service will not auto-restart on its own.\n",
                );
            }
        }
        s.push_str(&format!(
            "GP_WALLET_PASSWORD_FILE={}\n\n",
            self.wallet_password_file
        ));

        s.push_str("# --- managed state ---\n");
        s.push_str(&format!("GP_DATA_DIR={}\n", self.data_dir));
        s.push_str(&format!("GP_DB_PATH={}\n\n", self.db_path));

        s.push_str("# --- grin1 / Tor rail (advanced; default off) ---\n");
        if self.grin1_rail {
            s.push_str("GP_GRIN1_RAIL=on\n");
        } else {
            s.push_str("#GP_GRIN1_RAIL=on\n");
        }
        s
    }

    /// The exact three values to paste into the WooCommerce GoblinPay panel,
    /// plus the webhook URL and the private admin token, formatted for the
    /// wizard's final screen. This is the single copy-paste hand-off that
    /// replaces retyping matching secrets into WordPress by hand.
    pub fn woo_paste_block(&self) -> String {
        format!(
            "Now finish in WooCommerce -> Settings -> Payments -> GoblinPay (Grin):\n\
             \n\
             \x20 GoblinPay URL:   {url}\n\
             \x20 API Token:       {api}\n\
             \x20 Webhook Secret:  {secret}\n\
             \x20 Matching mode:   Per-invoice identity (recommended)\n\
             \n\
             The plugin's Webhook Secret field shows the webhook URL to confirm; it is:\n\
             \x20 {webhook}\n\
             \n\
             Admin dashboard token (keep private): {admin}",
            url = self.public_url,
            api = self.api_token,
            secret = self.webhook_secret,
            webhook = self.webhook_url,
            admin = self.admin_token,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_shapes_and_uniqueness() {
        let api = gen_api_token();
        assert!(api.starts_with("gp_live_"), "got {api}");
        assert_eq!(api.len(), "gp_live_".len() + 32);
        assert!(gen_admin_token().starts_with("gpadm_"));
        assert!(gen_webhook_secret().starts_with("whsec_"));
        // Hex bodies only.
        assert!(api["gp_live_".len()..]
            .chars()
            .all(|c| c.is_ascii_hexdigit()));
        // CSPRNG: two draws must differ.
        assert_ne!(gen_api_token(), gen_api_token());
        assert_ne!(gen_entropy_32(), gen_entropy_32());
    }

    #[test]
    fn password_validation_and_match() {
        // Empty is the only hard rejection (grin-wallet-faithful: the operator
        // picks their own password).
        assert!(validate_password("").is_err());
        assert!(validate_password("hunter2").is_ok());
        assert!(validate_password("a").is_ok());
        // Confirm-to-match: exact equality, nothing normalized.
        assert!(passwords_match("s3cret pass", "s3cret pass"));
        assert!(!passwords_match("s3cret", "s3cret "));
        assert!(!passwords_match("abc", "abd"));
    }

    #[test]
    fn restart_mode_parsing_defaults_unattended() {
        // Enter / blank / unknown -> the default (unattended).
        assert_eq!(parse_restart_mode(""), RestartMode::Unattended);
        assert_eq!(parse_restart_mode("  "), RestartMode::Unattended);
        assert_eq!(parse_restart_mode("1"), RestartMode::Unattended);
        assert_eq!(parse_restart_mode("U"), RestartMode::Unattended);
        assert_eq!(parse_restart_mode("Unattended"), RestartMode::Unattended);
        assert_eq!(parse_restart_mode("what"), RestartMode::Unattended);
        // Manual only on an explicit manual answer.
        assert_eq!(parse_restart_mode("2"), RestartMode::Manual);
        assert_eq!(parse_restart_mode("m"), RestartMode::Manual);
        assert_eq!(parse_restart_mode(" MANUAL "), RestartMode::Manual);
        assert_eq!(RestartMode::Unattended.as_str(), "unattended");
        assert_eq!(RestartMode::Manual.as_str(), "manual");
    }

    #[test]
    fn restart_mode_with_default_preserves_on_empty() {
        // Empty / unknown -> the caller's default (reconfigure preserves the
        // current mode rather than silently forcing unattended).
        assert_eq!(
            parse_restart_mode_default("", RestartMode::Manual),
            RestartMode::Manual
        );
        assert_eq!(
            parse_restart_mode_default("  ", RestartMode::Manual),
            RestartMode::Manual
        );
        assert_eq!(
            parse_restart_mode_default("what", RestartMode::Manual),
            RestartMode::Manual
        );
        // An explicit answer overrides the default in either direction.
        assert_eq!(
            parse_restart_mode_default("1", RestartMode::Manual),
            RestartMode::Unattended
        );
        assert_eq!(
            parse_restart_mode_default("unattended", RestartMode::Manual),
            RestartMode::Unattended
        );
        assert_eq!(
            parse_restart_mode_default("2", RestartMode::Unattended),
            RestartMode::Manual
        );
    }

    #[test]
    fn normalize_bind_trims_and_defaults() {
        assert_eq!(normalize_bind(""), "127.0.0.1:8080");
        assert_eq!(normalize_bind("   "), "127.0.0.1:8080");
        assert_eq!(normalize_bind("  0.0.0.0:9000 "), "0.0.0.0:9000");
    }

    #[test]
    fn parse_env_file_skips_comments_and_splits_first_eq() {
        let text = "\
            # a comment\n\
            \n\
            GP_BIND=127.0.0.1:8080\n\
            GP_PUBLIC_URL=https://pay.shop.com\n\
            #GP_GRIN1_RAIL=on\n\
            GP_RELAYS=wss://a,wss://b\n\
            GP_WEBHOOK_URL=https://s/wp-json?x=1=2\n";
        let pairs = parse_env_file(text);
        assert_eq!(pairs.len(), 4);
        assert!(pairs.contains(&("GP_BIND".to_string(), "127.0.0.1:8080".to_string())));
        assert!(pairs.contains(&("GP_RELAYS".to_string(), "wss://a,wss://b".to_string())));
        // Split on the FIRST '=' only, so values may contain '='.
        assert!(pairs.contains(&(
            "GP_WEBHOOK_URL".to_string(),
            "https://s/wp-json?x=1=2".to_string()
        )));
        // The commented rail line is not a pair.
        assert!(!pairs.iter().any(|(k, _)| k == "#GP_GRIN1_RAIL"));
    }

    #[test]
    fn render_env_round_trips_through_parse_env_file() {
        // The wizard's output parses back into the same non-secret values, which
        // is exactly how a bare first run boots from what it just wrote.
        let env = sample_params().render_env();
        let pairs: std::collections::HashMap<String, String> =
            parse_env_file(&env).into_iter().collect();
        assert_eq!(pairs.get("GP_BIND").unwrap(), "127.0.0.1:8080");
        assert_eq!(
            pairs.get("GP_PUBLIC_URL").unwrap(),
            "https://pay.myshop.com"
        );
        assert_eq!(pairs.get("GP_RELAY_MODE").unwrap(), "external");
        assert_eq!(pairs.get("GP_NODE_URL").unwrap(), "https://main.gri.mw");
    }

    #[test]
    fn seed_ack_requires_explicit_yes() {
        // No affirmative default: only y/yes acknowledge the written backup.
        assert!(parse_ack("y"));
        assert!(parse_ack("YES"));
        assert!(parse_ack("  yes "));
        assert!(!parse_ack(""));
        assert!(!parse_ack("n"));
        assert!(!parse_ack("later"));
    }

    #[test]
    fn manual_dropin_repoints_credential_to_tmpfs() {
        let d = render_manual_dropin(RUNTIME_WALLET_PASSWORD_FILE);
        // Resets the base unit's persistent credential, then reads the tmpfs one.
        assert!(d.contains("LoadCredential=\n"));
        assert!(d.contains("LoadCredential=gp_wallet_password:/run/goblinpay/wallet_password"));
        // Documents the systemd-ask-password start and the tmpfs rationale.
        assert!(d.contains("systemd-ask-password"));
        assert!(d.contains("tmpfs"));
        assert!(d.contains("[Service]"));
    }

    #[test]
    fn normalize_url_trims_and_requires_scheme() {
        assert_eq!(
            normalize_url("  https://pay.shop.com/  ").unwrap(),
            "https://pay.shop.com"
        );
        assert_eq!(
            normalize_url("http://127.0.0.1:8080").unwrap(),
            "http://127.0.0.1:8080"
        );
        assert!(normalize_url("pay.shop.com").is_err());
        assert!(normalize_url("").is_err());
        assert!(normalize_url("   ").is_err());
    }

    #[test]
    fn base_path_extracts_the_mount_prefix() {
        // Subdomain / root: no prefix.
        assert_eq!(base_path("https://pay.myshop.com"), "");
        assert_eq!(base_path("https://pay.myshop.com/"), "");
        assert_eq!(base_path("http://127.0.0.1:8080"), "");
        // Path hosting (zero new DNS): the path is the prefix, no trailing slash.
        assert_eq!(base_path("https://myshop.com/pay"), "/pay");
        assert_eq!(base_path("https://myshop.com/pay/"), "/pay");
        assert_eq!(base_path("https://myshop.com/shop/till"), "/shop/till");
    }

    #[test]
    fn webhook_url_appends_receiver_path() {
        assert_eq!(
            webhook_url_from_shop("https://myshop.com/").unwrap(),
            "https://myshop.com/wp-json/goblinpay/v1/webhook"
        );
        assert!(webhook_url_from_shop("myshop.com").is_err());
    }

    #[test]
    fn currencies_default_and_parse() {
        assert_eq!(parse_currencies(""), vec!["usd"]);
        assert_eq!(parse_currencies("   "), vec!["usd"]);
        assert_eq!(
            parse_currencies("USD, eur , GBP,"),
            vec!["usd", "eur", "gbp"]
        );
    }

    #[test]
    fn yes_no_defaulting() {
        assert!(!parse_yes_no("", false));
        assert!(parse_yes_no("", true));
        assert!(parse_yes_no("Y", false));
        assert!(parse_yes_no("yes", false));
        assert!(!parse_yes_no("n", true));
        assert!(!parse_yes_no("no", true));
        // Unknown falls back to the default (never traps the operator).
        assert!(!parse_yes_no("maybe", false));
        assert!(parse_yes_no("maybe", true));
    }

    #[test]
    fn select_node_picks_first_healthy_and_falls_back() {
        // First healthy wins.
        let all_ok = select_node(CURATED_NODES, |_| true).unwrap();
        assert_eq!(all_ok, CURATED_NODES[0]);
        // Leader down -> next candidate.
        let fallback = select_node(CURATED_NODES, |u| u != CURATED_NODES[0]).unwrap();
        assert_eq!(fallback, CURATED_NODES[1]);
        // All down -> None.
        assert!(select_node(CURATED_NODES, |_| false).is_none());
        // Probe is only called until the first hit (short-circuit).
        let mut calls = 0;
        let _ = select_node(CURATED_NODES, |_| {
            calls += 1;
            true
        });
        assert_eq!(calls, 1);
    }

    fn sample_params() -> SetupParams {
        SetupParams {
            bind: "127.0.0.1:8080".into(),
            public_url: "https://pay.myshop.com".into(),
            webhook_url: "https://myshop.com/wp-json/goblinpay/v1/webhook".into(),
            node_url: "https://main.gri.mw".into(),
            relays: DEFAULT_RELAYS.iter().map(|s| s.to_string()).collect(),
            currencies: vec!["usd".into()],
            grin1_rail: false,
            api_token: "gp_live_deadbeefdeadbeefdeadbeefdeadbeef".into(),
            admin_token: "gpadm_0011223344556677001122334455667".into(),
            webhook_secret: "whsec_abcdef0123456789abcdef0123456789".into(),
            data_dir: "/var/lib/goblinpay/gp-data".into(),
            db_path: "/var/lib/goblinpay/goblinpay.db".into(),
            wallet_password_file: "/etc/goblinpay/secrets/wallet_password".into(),
            restart_mode: RestartMode::Unattended,
        }
    }

    #[test]
    fn render_env_has_the_right_couplings_and_no_seed() {
        let env = sample_params().render_env();
        // The listen address is written (loopback default).
        assert!(env.contains("GP_BIND=127.0.0.1:8080"));
        // External relay pool, both relays present.
        assert!(env.contains("GP_RELAY_MODE=external"));
        assert!(env.contains("GP_RELAYS=wss://relay.floonet.dev,wss://offchain.pub"));
        // Webhook URL + secret travel together (config.rs validates this).
        assert!(env.contains("GP_WEBHOOK_URL=https://myshop.com/wp-json/goblinpay/v1/webhook"));
        assert!(env.contains("GP_WEBHOOK_SECRET=whsec_"));
        // Tokens are in the env file (O4).
        assert!(env.contains("GP_API_TOKEN=gp_live_"));
        assert!(env.contains("GP_ADMIN_TOKEN=gpadm_"));
        // Password by file reference, never inlined; operator-chosen, not
        // auto-generated (no such wording anywhere).
        assert!(env.contains("GP_WALLET_PASSWORD_FILE=/etc/goblinpay/secrets/wallet_password"));
        assert!(!env.contains("GP_WALLET_PASSWORD="));
        assert!(!env.to_lowercase().contains("auto-generat"));
        // Unattended mode is disclosed honestly (host-sealed + the trade-off).
        assert!(env.contains("UNATTENDED"));
        assert!(env.to_lowercase().contains("host"));
        assert!(env.to_lowercase().contains("compromise"));
        // The Grin seed is NEVER in the env (O2).
        assert!(!env.contains("GP_MNEMONIC"));
        // grin1 rail off -> commented out, not armed.
        assert!(env.contains("#GP_GRIN1_RAIL=on"));
        assert!(!env.contains("\nGP_GRIN1_RAIL=on"));

        // With the rail on, it is armed (uncommented).
        let mut p = sample_params();
        p.grin1_rail = true;
        let env = p.render_env();
        assert!(env.contains("\nGP_GRIN1_RAIL=on"));
    }

    #[test]
    fn render_env_manual_mode_says_nothing_on_disk() {
        let mut p = sample_params();
        p.restart_mode = RestartMode::Manual;
        p.wallet_password_file = RUNTIME_WALLET_PASSWORD_FILE.into();
        let env = p.render_env();
        assert!(env.contains("MANUAL"));
        assert!(env.to_lowercase().contains("not stored on disk"));
        assert!(env.contains("GP_WALLET_PASSWORD_FILE=/run/goblinpay/wallet_password"));
        // Still never inlines the password, and never claims auto-generation.
        assert!(!env.contains("GP_WALLET_PASSWORD="));
        assert!(!env.to_lowercase().contains("auto-generat"));
    }

    #[test]
    fn woo_paste_block_lists_the_three_values() {
        let block = sample_params().woo_paste_block();
        assert!(block.contains("GoblinPay URL:   https://pay.myshop.com"));
        assert!(block.contains("API Token:       gp_live_deadbeefdeadbeefdeadbeefdeadbeef"));
        assert!(block.contains("Webhook Secret:  whsec_abcdef0123456789abcdef0123456789"));
        assert!(block.contains("Per-invoice identity (recommended)"));
        assert!(block.contains("wp-json/goblinpay/v1/webhook"));
        assert!(block.contains("Admin dashboard token (keep private): gpadm_"));
    }
}
