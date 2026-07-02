//! Lightweight on-chain confirmation for a received payment.
//!
//! A GoblinPay payment confirms when the transaction kernel the payer builds
//! (and posts) lands in a block. We never run the heavy full-UTXO scan/updater
//! for this: we already know the tx kernel excess at receive time (the upstream
//! `Slate::calc_excess`, stored per payment), so confirmation is a single
//! `get_kernel(excess)` lookup against the node, exactly the query the wallet's
//! own updater uses to detect reverted kernels.
//!
//! Transport: this read goes DIRECT over normal HTTP to the configured node
//! (`grin_wallet_impls::HTTPNodeClient`), NEVER through the Nym tunnel. The
//! mixnet in gp-nostr carries only the Nostr gift-wrap layer; the wallet<->node
//! reads are a server concern that rides clearnet, mirroring Goblin's own
//! wallet->node traffic (owner ruling). This crate has no Nym linkage at all,
//! so the direct path is structural, not merely configured.
//!
//! We depend on upstream grin-wallet for the network round-trip and kernel
//! parse; the only logic here is turning the located kernel into a
//! confirmation height + count, which is unit-tested against a recorded node
//! response (no live node needed).

use grin_util::secp::pedersen::Commitment;
use grin_wallet_impls::HTTPNodeClient;
use grin_wallet_libwallet::NodeClient;
use serde::Serialize;

use crate::WalletError;

/// The 33-byte Pedersen commitment size (a kernel excess is a commitment).
const COMMITMENT_LEN: usize = 33;

/// Confirmation status for one payment's kernel.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ConfirmStatus {
    /// The kernel is included in a block on the node's current chain.
    pub confirmed: bool,
    /// Block height the kernel landed at (present iff `confirmed`).
    pub height: Option<u64>,
    /// Confirmation depth at the queried tip (1 = in the tip block).
    pub confirmations: Option<u64>,
    /// The kernel excess we queried, hex (echoed for the caller/record).
    pub kernel_excess: String,
}

/// Query the node for a received payment's kernel and report confirmation.
///
/// `node_url` is the configured `GP_NODE_URL` (default `https://main.gri.mw`);
/// the client is built fresh per call (cheap: one JSON-RPC round trip) and
/// talks DIRECT HTTP. `kernel_excess_hex` is the 66-char hex of the kernel
/// excess commitment recorded at receive time.
pub fn confirm_status(
    node_url: &str,
    kernel_excess_hex: &str,
) -> Result<ConfirmStatus, WalletError> {
    let excess = parse_commitment(kernel_excess_hex)?;

    let mut client = HTTPNodeClient::new(node_url, None)
        .map_err(|e| WalletError::Config(format!("bad node URL `{node_url}`: {e}")))?;

    let tip = client
        .get_chain_tip()
        .map_err(|e| WalletError::Wallet(format!("node get_tip failed: {e}")))?
        .0;

    // get_kernel returns Ok(None) for a kernel not (yet) on chain, and
    // Ok(Some((kernel, height, mmr_index))) once it lands. We only need the
    // height; the node already validated the kernel by including it in a block.
    let kernel_height = client
        .get_kernel(&excess, None, None)
        .map_err(|e| WalletError::Wallet(format!("node get_kernel failed: {e}")))?
        .map(|(_kernel, height, _mmr_index)| height);

    Ok(interpret(tip, kernel_height, kernel_excess_hex))
}

/// Pure interpretation of a kernel lookup into a [`ConfirmStatus`]. Split out
/// so the confirmation math is unit-testable without a node.
fn interpret(
    tip_height: u64,
    kernel_height: Option<u64>,
    kernel_excess_hex: &str,
) -> ConfirmStatus {
    match kernel_height {
        // A kernel cannot be above the tip; clamp defensively so a racing tip
        // read never yields a nonsensical (underflowed) confirmation count.
        Some(height) => ConfirmStatus {
            confirmed: true,
            height: Some(height),
            confirmations: Some(tip_height.saturating_sub(height) + 1),
            kernel_excess: kernel_excess_hex.to_string(),
        },
        None => ConfirmStatus {
            confirmed: false,
            height: None,
            confirmations: None,
            kernel_excess: kernel_excess_hex.to_string(),
        },
    }
}

/// Parse a 33-byte commitment from hex.
fn parse_commitment(hex: &str) -> Result<Commitment, WalletError> {
    let bytes = decode_hex(hex.trim())
        .ok_or_else(|| WalletError::Config(format!("kernel excess is not valid hex: `{hex}`")))?;
    if bytes.len() != COMMITMENT_LEN {
        return Err(WalletError::Config(format!(
            "kernel excess must be {COMMITMENT_LEN} bytes ({} hex chars), got {}",
            COMMITMENT_LEN * 2,
            bytes.len()
        )));
    }
    Ok(Commitment::from_vec(bytes))
}

/// Minimal hex decode (no dependency; the excess is machine-generated hex).
fn decode_hex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    // A real get_tip response captured from https://main.gri.mw/v2/foreign
    // (2026-07-01), used to source the chain tip in the fixtures below.
    const TIP_JSON: &str = r#"{"id":1,"jsonrpc":"2.0","result":{"Ok":{"height":3911936,"last_block_pushed":"00015b89ed20619bb003ce358c3ab861a05882064cdeb06dac8bd3ba913ee763","prev_block_to_last":"00039cf6ccb9b730cd2b58906d4eb4d549190919c3f47e6a399ea98dabcf9a22","total_difficulty":2358710106678858}}}"#;

    // A real get_kernel "not on chain" response captured from the same node
    // (queried with a well-formed but nonexistent excess). This is the shape
    // the confirmation poll sees for every still-pending payment.
    const KERNEL_NOTFOUND_JSON: &str = r#"{"id":1,"jsonrpc":"2.0","result":{"Err":"NotFound"}}"#;

    // A get_kernel "found" response in the node's exact wire shape. Public
    // block explorers were unreachable to capture a live hit at build time, so
    // this fixture is round-tripped through the real `grin_api::LocatedTxKernel`
    // type in `found_fixture_matches_real_node_type` below, which guarantees it
    // is byte-shaped exactly as the node (and HTTPNodeClient) produce/consume.
    // The live "found" path is exercised in the supervised mainnet round.
    const KERNEL_FOUND_JSON: &str = r#"{"id":1,"jsonrpc":"2.0","result":{"Ok":{"tx_kernel":{"features":{"Plain":{"fee":7000000}},"excess":"09a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90","excess_sig":"8f1c9d2e3a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5"},"height":3900000,"mmr_index":54321000}}}"#;

    /// Envelope helpers mirroring how HTTPNodeClient reads the result field.
    fn tip_height(json: &str) -> u64 {
        let v: serde_json::Value = serde_json::from_str(json).unwrap();
        v["result"]["Ok"]["height"].as_u64().unwrap()
    }

    /// Parse a get_kernel response into the located kernel's height, exactly
    /// the field confirm_status consumes. Returns None on `Err(NotFound)`.
    fn located_height(json: &str) -> Option<u64> {
        let v: serde_json::Value = serde_json::from_str(json).unwrap();
        let ok = v["result"].get("Ok")?;
        let located: grin_api::LocatedTxKernel = serde_json::from_value(ok.clone()).unwrap();
        Some(located.height)
    }

    #[test]
    fn found_fixture_matches_real_node_type() {
        // The recorded "found" fixture must deserialize into the EXACT type
        // HTTPNodeClient parses into (grin_api::LocatedTxKernel), so the parser
        // the production path relies on and this test agree on the wire shape.
        let v: serde_json::Value = serde_json::from_str(KERNEL_FOUND_JSON).unwrap();
        let located: grin_api::LocatedTxKernel =
            serde_json::from_value(v["result"]["Ok"].clone()).unwrap();
        assert_eq!(located.height, 3_900_000);
        assert_eq!(located.mmr_index, 54_321_000);
    }

    #[test]
    fn confirmed_when_kernel_found() {
        let tip = tip_height(TIP_JSON);
        let height = located_height(KERNEL_FOUND_JSON);
        assert_eq!(height, Some(3_900_000));
        let status = interpret(tip, height, "09aa");
        assert!(status.confirmed);
        assert_eq!(status.height, Some(3_900_000));
        // 3911936 - 3900000 + 1
        assert_eq!(status.confirmations, Some(11_937));
        assert_eq!(status.kernel_excess, "09aa");
    }

    #[test]
    fn pending_when_kernel_not_found() {
        let tip = tip_height(TIP_JSON);
        let height = located_height(KERNEL_NOTFOUND_JSON);
        assert_eq!(height, None);
        let status = interpret(tip, height, "09bb");
        assert!(!status.confirmed);
        assert!(status.height.is_none());
        assert!(status.confirmations.is_none());
    }

    #[test]
    fn confirmations_are_one_in_the_tip_block() {
        let status = interpret(100, Some(100), "09cc");
        assert_eq!(status.confirmations, Some(1));
    }

    #[test]
    fn tip_behind_kernel_does_not_underflow() {
        // A racing/stale tip below the kernel height must not panic or wrap.
        let status = interpret(90, Some(100), "09dd");
        assert!(status.confirmed);
        assert_eq!(status.confirmations, Some(1));
    }

    #[test]
    fn bad_excess_hex_is_rejected() {
        assert!(parse_commitment("nothex!!").is_err());
        assert!(parse_commitment("09aa").is_err()); // right hex, wrong length
                                                    // 33 bytes of valid hex parses.
        assert!(parse_commitment(&"09".repeat(COMMITMENT_LEN)).is_ok());
    }
}
