//! Server-rendered QR codes as SVG, zero JavaScript.
//!
//! The QR is always generated at error-correction level **H** (tolerates
//! ~30% occlusion) so an optional centered logo, sized to ~22% of the code,
//! never breaks scannability. The logo is a white rounded backing rectangle
//! plus one `<image>` element referencing a statically served asset (the
//! Goblin mark by default, or the operator's own via `GP_QR_LOGO`). With no
//! logo it is a plain black-on-white QR.
//!
//! Rendering is hand-rolled (one `<path>` of the dark modules) so the crate
//! needs only the `qrcode` matrix, not its image/SVG feature or any raster
//! dependency, and we keep full control of the logo overlay.

use qrcode::{Color, EcLevel, QrCode};

/// Logo size as a fraction of the QR width (safe under ECC level H).
pub const LOGO_FRACTION: f64 = 0.22;
/// Quiet zone in modules on every side (the QR spec's required margin).
const QUIET: u32 = 4;

/// Failed to build a QR (e.g. the payload exceeds the largest QR version).
#[derive(Debug)]
pub struct QrError(pub String);

impl std::fmt::Display for QrError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "qr error: {}", self.0)
    }
}

impl std::error::Error for QrError {}

/// Render `data` as an SVG string at ECC level H. When `logo_href` is set, a
/// white rounded rectangle plus a centered `<image>` are overlaid. The SVG
/// scales to its container; a `viewBox` in module units keeps it crisp.
pub fn svg(data: &str, logo_href: Option<&str>) -> Result<String, QrError> {
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

    if let Some(href) = logo_href {
        // Center a logo sized to LOGO_FRACTION of the code (module units),
        // on a slightly larger white rounded backing so it reads cleanly.
        let logo = (dim as f64 * LOGO_FRACTION).round();
        let pad = 1.0_f64;
        let back = logo + 2.0 * pad;
        let center = dim as f64 / 2.0;
        let back_x = center - back / 2.0;
        let back_y = center - back / 2.0;
        let logo_x = center - logo / 2.0;
        let logo_y = center - logo / 2.0;
        let radius = back * 0.18;
        svg.push_str(&format!(
            "<rect x=\"{back_x:.2}\" y=\"{back_y:.2}\" width=\"{back:.2}\" height=\"{back:.2}\" \
             rx=\"{radius:.2}\" ry=\"{radius:.2}\" fill=\"#ffffff\"/>\
             <image href=\"{href}\" x=\"{logo_x:.2}\" y=\"{logo_y:.2}\" \
             width=\"{logo:.2}\" height=\"{logo:.2}\" preserveAspectRatio=\"xMidYMid meet\"/>"
        ));
    }

    svg.push_str("</svg>");
    Ok(svg)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generates_valid_svg_at_ecc_h() {
        let out = svg("grin1qtestaddressdata", None).unwrap();
        assert!(out.starts_with("<svg"));
        assert!(out.ends_with("</svg>"));
        assert!(out.contains("viewBox"));
        // No script, no external CSS: zero JS by construction.
        assert!(!out.contains("<script"));
        assert!(out.contains("fill=\"#000000\""));
    }

    #[test]
    fn embeds_a_center_logo_when_requested() {
        let plain = svg("nprofile1qtest", None).unwrap();
        let logoed = svg("nprofile1qtest", Some("/static/goblin-mark.svg")).unwrap();
        assert!(!plain.contains("<image"));
        assert!(logoed.contains("<image"));
        assert!(logoed.contains("/static/goblin-mark.svg"));
        // The backing rounded rect is present.
        assert!(logoed.contains("rx="));
    }

    #[test]
    fn large_payloads_still_render() {
        // A long nprofile-plus-relays string must not overflow QR capacity at
        // ECC H (this is well within version-40 limits).
        let data = "nprofile1".to_string() + &"a".repeat(300);
        assert!(svg(&data, None).is_ok());
    }

    #[test]
    fn quiet_zone_is_present() {
        let out = svg("x", None).unwrap();
        // viewBox dimension exceeds the module count by 2*QUIET.
        let code = QrCode::with_error_correction_level("x".as_bytes(), EcLevel::H).unwrap();
        let dim = code.width() as u32 + 2 * QUIET;
        assert!(out.contains(&format!("viewBox=\"0 0 {dim} {dim}\"")));
    }
}
