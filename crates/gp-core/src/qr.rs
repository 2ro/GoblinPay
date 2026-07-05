//! Server-rendered QR codes as SVG, zero JavaScript.
//!
//! The QR is always generated at error-correction level **H** (tolerates
//! ~30% occlusion) so an optional centered logo, sized to ~22% of the code,
//! never breaks scannability. The default is a plain black-on-white QR. An
//! operator may opt in to a center logo (`GP_QR_LOGO`): the built-in Goblin
//! mark is drawn as inline vector shapes (not a referenced `<image>`) so the
//! whole QR is self-contained and renders identically wherever the SVG is
//! embedded, including cross-origin connector pages (WooCommerce, Medusa)
//! where a `/static/...` href would 404; a custom image URL is also accepted.
//!
//! Rendering is hand-rolled (one `<path>` of the dark modules) so the crate
//! needs only the `qrcode` matrix, not its image/SVG feature or any raster
//! dependency, and we keep full control of the logo overlay.

use qrcode::{Color, EcLevel, QrCode};

/// Logo size as a fraction of the QR width (safe under ECC level H).
pub const LOGO_FRACTION: f64 = 0.22;
/// Quiet zone in modules on every side (the QR spec's required margin).
const QUIET: u32 = 4;

/// The center logo drawn over a QR code.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Logo<'a> {
    /// No center logo: a plain black-on-white QR.
    None,
    /// The built-in Goblin mark, inlined as vector shapes. Self-contained, so
    /// it renders on any origin (opt-in via `GP_QR_LOGO=builtin`).
    Builtin,
    /// An operator-supplied image referenced by URL (`GP_QR_LOGO=<url>`). The
    /// operator is responsible for it being reachable from wherever the QR is
    /// shown (use an absolute URL for cross-origin connector embeds).
    Href(&'a str),
}

/// Failed to build a QR (e.g. the payload exceeds the largest QR version).
#[derive(Debug)]
pub struct QrError(pub String);

impl std::fmt::Display for QrError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "qr error: {}", self.0)
    }
}

impl std::error::Error for QrError {}

/// Render `data` as an SVG string at ECC level H. A `Logo` other than
/// `Logo::None` overlays a white rounded backing rectangle plus the centered
/// mark. The SVG scales to its container; a `viewBox` in module units keeps it
/// crisp.
pub fn svg(data: &str, logo: Logo<'_>) -> Result<String, QrError> {
    let code = QrCode::with_error_correction_level(data.as_bytes(), EcLevel::H)
        .map_err(|e| QrError(e.to_string()))?;
    let width = code.width() as u32;
    let colors = code.to_colors();
    let dim = width + 2 * QUIET;

    // One path for every dark module (each a 1x1 unit square), offset by the
    // quiet zone.
    let mut path = String::new();
    for y in 0..width {
        for x in 0..width {
            if colors[(y * width + x) as usize] == Color::Dark {
                let px = x + QUIET;
                let py = y + QUIET;
                path.push_str(&format!("M{px} {py}h1v1h-1z"));
            }
        }
    }

    let mut svg = format!(
        "<svg xmlns=\"http://www.w3.org/2000/svg\" viewBox=\"0 0 {dim} {dim}\" \
         shape-rendering=\"crispEdges\" role=\"img\" aria-label=\"Payment QR code\" \
         class=\"qr\">\
         <rect width=\"{dim}\" height=\"{dim}\" fill=\"#ffffff\"/>\
         <path d=\"{path}\" fill=\"#000000\"/>"
    );

    if logo != Logo::None {
        // Center a logo sized to LOGO_FRACTION of the code (module units),
        // on a slightly larger white rounded backing so it reads cleanly.
        let size = (dim as f64 * LOGO_FRACTION).round();
        let pad = 1.0_f64;
        let back = size + 2.0 * pad;
        let center = dim as f64 / 2.0;
        let back_x = center - back / 2.0;
        let back_y = center - back / 2.0;
        let logo_x = center - size / 2.0;
        let logo_y = center - size / 2.0;
        let radius = back * 0.18;
        svg.push_str(&format!(
            "<rect x=\"{back_x:.2}\" y=\"{back_y:.2}\" width=\"{back:.2}\" height=\"{back:.2}\" \
             rx=\"{radius:.2}\" ry=\"{radius:.2}\" fill=\"#ffffff\"/>"
        ));
        match logo {
            Logo::Builtin => svg.push_str(&goblin_mark(logo_x, logo_y, size)),
            Logo::Href(href) => svg.push_str(&format!(
                "<image href=\"{href}\" x=\"{logo_x:.2}\" y=\"{logo_y:.2}\" \
                 width=\"{size:.2}\" height=\"{size:.2}\" preserveAspectRatio=\"xMidYMid meet\"/>"
            )),
            Logo::None => {}
        }
    }

    svg.push_str("</svg>");
    Ok(svg)
}

/// The Goblin mark as inline SVG shapes, scaled to `size` units and placed at
/// `(x, y)` in the QR's module coordinate space. Mirrors `static/goblin-mark.svg`
/// (a 64-unit design) but drops the gold tile: on the white backing the head
/// reads as a black mark with white eyes and mouth. Emits only `<path>` and
/// `<circle>` inside a translated/scaled `<g>` so downstream SVG sanitizers
/// (e.g. the WooCommerce connector's `wp_kses` allow-list) pass it unchanged.
fn goblin_mark(x: f64, y: f64, size: f64) -> String {
    let scale = size / 64.0;
    format!(
        "<g transform=\"translate({x:.2} {y:.2}) scale({scale:.4})\">\
         <path fill=\"#201d09\" d=\"M20 22c0-3 3-5 6-4l6 3 6-3c3-1 6 1 6 4v10c0 8-6 14-12 14S20 40 20 32z\"/>\
         <circle cx=\"26\" cy=\"30\" r=\"3\" fill=\"#ffffff\"/>\
         <circle cx=\"38\" cy=\"30\" r=\"3\" fill=\"#ffffff\"/>\
         <path fill=\"#ffffff\" d=\"M28 40h8l-4 5z\"/></g>"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generates_valid_svg_at_ecc_h() {
        let out = svg("grin1qtestaddressdata", Logo::None).unwrap();
        assert!(out.starts_with("<svg"));
        assert!(out.ends_with("</svg>"));
        assert!(out.contains("viewBox"));
        // No script, no external CSS: zero JS by construction.
        assert!(!out.contains("<script"));
        assert!(out.contains("fill=\"#000000\""));
    }

    #[test]
    fn inlines_the_builtin_goblin_mark() {
        let plain = svg("nprofile1qtest", Logo::None).unwrap();
        let marked = svg("nprofile1qtest", Logo::Builtin).unwrap();
        assert!(!plain.contains("<g transform"));
        // The mark is inlined as vector shapes, not an external <image> ref,
        // so the QR stays self-contained on any origin.
        assert!(marked.contains("<g transform"));
        assert!(!marked.contains("<image"));
        assert!(marked.contains("<circle"));
        // The backing rounded rect is present.
        assert!(marked.contains("rx="));
    }

    #[test]
    fn embeds_an_external_image_for_a_custom_href() {
        let logoed = svg("nprofile1qtest", Logo::Href("https://cdn.example/logo.svg")).unwrap();
        assert!(logoed.contains("<image"));
        assert!(logoed.contains("https://cdn.example/logo.svg"));
        assert!(logoed.contains("rx="));
    }

    #[test]
    fn large_payloads_still_render() {
        // A long nprofile-plus-relays string must not overflow QR capacity at
        // ECC H (this is well within version-40 limits).
        let data = "nprofile1".to_string() + &"a".repeat(300);
        assert!(svg(&data, Logo::Builtin).is_ok());
    }

    #[test]
    fn quiet_zone_is_present() {
        let out = svg("x", Logo::None).unwrap();
        // viewBox dimension exceeds the module count by 2*QUIET.
        let code = QrCode::with_error_correction_level("x".as_bytes(), EcLevel::H).unwrap();
        let dim = code.width() as u32 + 2 * QUIET;
        assert!(out.contains(&format!("viewBox=\"0 0 {dim} {dim}\"")));
    }
}
