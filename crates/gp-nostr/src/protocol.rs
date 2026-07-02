//! Goblin payment message protocol over NIP-17 (kind 14 rumors), ported from
//! `goblin/src/nostr/protocol.rs` minus the request/void control messages a
//! receive-only server never sends or honors.
//!
//! Content layout: a one-line human readable preamble, a blank line and the
//! raw slatepack armor. The per-payment note travels in the standard
//! `subject` tag; a `goblin` tag marks the protocol version. Classification
//! NEVER trusts tags — only the parsed slate (gp-wallet enforces S1).

use nostr_sdk::{Tag, TagKind, Tags};

/// Maximum gift wrap content size accepted before unwrapping.
pub const MAX_WRAP_CONTENT: usize = 64 * 1024;
/// Maximum rumor content size accepted after unwrapping.
pub const MAX_RUMOR_CONTENT: usize = 32 * 1024;
/// Maximum slatepack armor size accepted.
pub const MAX_SLATEPACK: usize = 30 * 1024;
/// Maximum note length in characters after sanitization.
pub const MAX_NOTE_CHARS: usize = 256;
/// Protocol marker tag name.
pub const GOBLIN_TAG: &str = "goblin";
/// Protocol version value.
pub const PROTOCOL_VERSION: &str = "1";

/// Human readable preamble other NIP-17 clients render.
pub const PREAMBLE: &str =
    "[Goblin] GRIN payment message — open in Goblin (https://goblin.st) to process.";

const ARMOR_BEGIN: &str = "BEGINSLATEPACK.";
const ARMOR_END: &str = "ENDSLATEPACK.";

/// Sanitize a user note: strip control characters, collapse whitespace,
/// trim and cap the length. Returns `None` when nothing readable remains.
pub fn sanitize_note(raw: &str) -> Option<String> {
    let cleaned: String = raw
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    let collapsed = cleaned.split_whitespace().collect::<Vec<_>>().join(" ");
    let trimmed = collapsed.trim();
    if trimmed.is_empty() {
        return None;
    }
    Some(trimmed.chars().take(MAX_NOTE_CHARS).collect())
}

/// Build the kind-14 rumor content for a slatepack payment message.
pub fn build_payment_content(slatepack: &str) -> String {
    format!("{}\n\n{}", PREAMBLE, slatepack.trim())
}

/// Build rumor tags: protocol marker plus optional subject note.
pub fn build_rumor_tags(note: Option<&str>) -> Vec<Tag> {
    let mut tags = vec![Tag::custom(
        TagKind::custom(GOBLIN_TAG),
        [PROTOCOL_VERSION.to_string()],
    )];
    if let Some(note) = note.and_then(sanitize_note) {
        tags.push(Tag::custom(TagKind::custom("subject"), [note]));
    }
    tags
}

/// Extract exactly one slatepack armor block from rumor content.
/// More than one block, none at all, or an oversized block returns `None`.
/// (Same semantics as Goblin's non-greedy `BEGINSLATEPACK. .. ENDSLATEPACK.`
/// regex, hand-rolled so this crate needs no regex dependency.)
pub fn extract_slatepack(content: &str) -> Option<String> {
    if content.len() > MAX_RUMOR_CONTENT {
        return None;
    }
    let start = content.find(ARMOR_BEGIN)?;
    let end_rel = content[start..].find(ARMOR_END)?;
    let end = start + end_rel + ARMOR_END.len();
    // A second complete block after the first is ambiguous: refuse.
    let rest = &content[end..];
    if let Some(next) = rest.find(ARMOR_BEGIN) {
        if rest[next..].contains(ARMOR_END) {
            return None;
        }
    }
    let armor = content[start..end].trim().to_string();
    if armor.len() > MAX_SLATEPACK {
        return None;
    }
    Some(armor)
}

/// Read the sanitized subject (note) from rumor tags.
pub fn extract_subject(tags: &Tags) -> Option<String> {
    for tag in tags.iter() {
        let parts = tag.as_slice();
        if parts.first().map(|s| s.as_str()) == Some("subject") {
            if let Some(value) = parts.get(1) {
                return sanitize_note(value);
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    const PACK: &str = "BEGINSLATEPACK. 4H1qx1wHe668tFW yC2gfL8PPd8kSgv \
        pcXQhyRkHbyKHZg GN75o7uWoT3dkib R2tj1fFGN2FoRLY oeBPyKizupksgRT \
        dXFdjEuMUuktR5r gCiVBSXcHSWW3KW Y56LTQ9z3QwUWmE 8sRtwR9Bn8oNN5K \
        zYbR6XLkP8cSC7. ENDSLATEPACK.";

    #[test]
    fn extracts_single_slatepack() {
        let content = format!("{}\n\n{}", PREAMBLE, PACK);
        let got = extract_slatepack(&content).unwrap();
        assert!(got.starts_with("BEGINSLATEPACK."));
        assert!(got.ends_with("ENDSLATEPACK."));
    }

    #[test]
    fn rejects_no_slatepack() {
        assert!(extract_slatepack("hi there, no payment here").is_none());
        assert!(extract_slatepack("").is_none());
        assert!(extract_slatepack("BEGINSLATEPACK. truncated junk").is_none());
    }

    #[test]
    fn rejects_two_slatepacks() {
        let content = format!("{} {}", PACK, PACK);
        assert!(extract_slatepack(&content).is_none());
        // But trailing garbage with only a BEGIN marker is not a second block.
        let content = format!("{} BEGINSLATEPACK. trailing junk", PACK);
        assert!(extract_slatepack(&content).is_some());
    }

    #[test]
    fn rejects_oversize() {
        let huge = format!(
            "BEGINSLATEPACK. {} ENDSLATEPACK.",
            "A".repeat(MAX_SLATEPACK + 1)
        );
        assert!(extract_slatepack(&huge).is_none());
        let oversize_content = "x".repeat(MAX_RUMOR_CONTENT + 1);
        assert!(extract_slatepack(&oversize_content).is_none());
    }

    #[test]
    fn sanitizes_notes() {
        assert_eq!(sanitize_note("  lunch :)  "), Some("lunch :)".to_string()));
        assert_eq!(
            sanitize_note("a\u{0000}b\u{001b}[31mc"),
            Some("a b [31mc".to_string())
        );
        assert_eq!(
            sanitize_note("multi   space\n\nnewline"),
            Some("multi space newline".to_string())
        );
        assert_eq!(sanitize_note("\u{0007}\u{0008}"), None);
        assert_eq!(sanitize_note(""), None);
        let long = "y".repeat(MAX_NOTE_CHARS + 50);
        assert_eq!(
            sanitize_note(&long).unwrap().chars().count(),
            MAX_NOTE_CHARS
        );
    }

    #[test]
    fn builds_content_with_preamble() {
        let c = build_payment_content(PACK);
        assert!(c.starts_with(PREAMBLE));
        assert!(extract_slatepack(&c).is_some());
    }

    #[test]
    fn subject_round_trips_through_tags() {
        let tags = Tags::from_list(build_rumor_tags(Some("  order #42  ")));
        assert_eq!(extract_subject(&tags), Some("order #42".to_string()));
        let no_note = Tags::from_list(build_rumor_tags(None));
        assert_eq!(extract_subject(&no_note), None);
    }
}
