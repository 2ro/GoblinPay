//! Server-rendered QR codes as SVG, zero JavaScript.
//!
//! The QR is always generated at error-correction level **H** (tolerates
//! ~30% occlusion) so a centered logo, sized to ~18% of the code, never breaks
//! scannability. The built-in Goblin emblem is drawn as inline vector shapes
//! (not a referenced `<image>`) so the whole QR is self-contained and renders
//! identically wherever the SVG is embedded, including cross-origin connector
//! pages (WooCommerce, Medusa) where a `/static/...` href would 404; a custom
//! image URL is also accepted. The pay page always centers the emblem; the
//! plain code is available via `Logo::None`.
//!
//! The built-in emblem sits in a circular excavation (a clean round quiet area,
//! not a stamped-on tile), so it reads as a deliberate mark; operator-supplied
//! images keep a rounded-rect backing (a circle could clip a rectangular logo's
//! corners onto dark modules).
//!
//! Rendering is hand-rolled (one `<path>` of the dark modules) so the crate
//! needs only the `qrcode` matrix, not its image/SVG feature or any raster
//! dependency, and we keep full control of the logo overlay.

use qrcode::{Color, EcLevel, QrCode};

/// Logo size as a fraction of the QR width (safe under ECC level H; a modest
/// 18% keeps the emblem crisp and the occluded area well under H's ~30%).
pub const LOGO_FRACTION: f64 = 0.18;
/// Quiet zone in modules on every side (the QR spec's required margin).
const QUIET: u32 = 4;

/// The center logo drawn over a QR code.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Logo<'a> {
    /// No center logo: a plain black-on-white QR.
    None,
    /// The built-in Goblin emblem, inlined as vector shapes. Self-contained, so
    /// it renders on any origin (opt-in via `GP_QR_LOGO=builtin`; the pay page
    /// centers it by default).
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
/// `Logo::None` overlays a white backing (a circular excavation for the built-in
/// emblem, a rounded rectangle for a custom image) plus the centered mark. The
/// SVG scales to its container; a `viewBox` in module units keeps it crisp.
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
        // Center a logo sized to LOGO_FRACTION of the code (module units).
        let size = (dim as f64 * LOGO_FRACTION).round();
        let center = dim as f64 / 2.0;
        let logo_x = center - size / 2.0;
        let logo_y = center - size / 2.0;
        match logo {
            Logo::Builtin => {
                // A circular excavation with ~30% breathing room lets the
                // emblem float in clean negative space (a deliberate mark, not
                // a stamped-on tile). ~18% width plus this margin stays far
                // inside ECC-H's occlusion budget.
                let radius = size * 0.65;
                svg.push_str(&format!(
                    "<circle cx=\"{center:.2}\" cy=\"{center:.2}\" r=\"{radius:.2}\" \
                     fill=\"#ffffff\"/>"
                ));
                svg.push_str(&goblin_mark(logo_x, logo_y, size));
            }
            Logo::Href(href) => {
                // Operator images keep the rounded-rect backing.
                let pad = 1.0_f64;
                let back = size + 2.0 * pad;
                let back_x = center - back / 2.0;
                let back_y = center - back / 2.0;
                let radius = back * 0.18;
                svg.push_str(&format!(
                    "<rect x=\"{back_x:.2}\" y=\"{back_y:.2}\" width=\"{back:.2}\" \
                     height=\"{back:.2}\" rx=\"{radius:.2}\" ry=\"{radius:.2}\" fill=\"#ffffff\"/>\
                     <image href=\"{href}\" x=\"{logo_x:.2}\" y=\"{logo_y:.2}\" \
                     width=\"{size:.2}\" height=\"{size:.2}\" preserveAspectRatio=\"xMidYMid meet\"/>"
                ));
            }
            Logo::None => {}
        }
    }

    svg.push_str("</svg>");
    Ok(svg)
}

/// The two silhouette paths of the Goblin emblem (`Goblin_Logo_2.svg`), copied
/// verbatim from the source art. They are drawn in the art's own 600-unit,
/// y-flipped coordinate space (see `goblin_mark`), so the data must not be
/// transformed here.
const GOBLIN_PATH_0: &str = "M195 11784 c-515 -1551 98 -2966 1520 -3514 171 -66 171 -72 2 -72 -415 0 -893 215 -1273 572 -178 167 -181 163 -77 -83 478 -1130 1770 -1734 2963 -1384 283 83 309 101 420 292 376 648 1038 1116 1763 1245 l143 26 100 202 c887 1780 -911 3344 -3076 2675 l-170 -52 220 -14 c480 -32 818 -114 1118 -273 258 -137 548 -414 624 -597 l32 -76 -87 76 c-435 375 -938 524 -1557 461 -273 -28 -340 -39 -740 -120 -893 -182 -1449 24 -1756 650 l-98 200 -71 -214z";
const GOBLIN_PATH_1: &str = "M9720 10053 c0 -146 -256 -556 -441 -705 -381 -308 -766 -380 -1559 -290 -1178 133 -2048 -270 -2488 -1152 -57 -115 -92 -149 -92 -89 0 78 123 415 199 548 43 74 73 135 67 135 -25 0 -397 -184 -512 -253 -962 -578 -1594 -1675 -1594 -2767 0 -209 -2 -210 -154 -95 -393 297 -523 388 -751 525 -321 192 -571 311 -843 400 -290 95 -302 94 -242 -15 52 -95 166 -372 191 -465 9 -33 34 -121 56 -195 48 -161 120 -508 194 -935 118 -684 437 -1371 795 -1715 185 -178 324 -239 594 -262 144 -13 150 -15 147 -63 -1 -27 -14 -174 -28 -326 -83 -902 258 -1568 1037 -2024 139 -81 161 -80 127 4 -37 96 -85 369 -96 546 l-10 170 46 -60 c328 -431 869 -753 1497 -891 351 -77 1285 -67 1426 15 9 5 -104 50 -250 98 -653 218 -1499 778 -1704 1129 -43 73 -54 78 188 -79 230 -149 543 -303 750 -369 783 -249 1542 -242 2332 20 l274 91 106 -83 c298 -236 798 -328 1259 -231 197 42 196 38 32 169 -156 124 -344 356 -443 546 l-60 116 70 52 c544 408 783 906 627 1300 l-41 102 170 138 c442 355 584 624 813 1537 186 742 257 952 452 1328 l118 227 -145 -14 c-693 -68 -1425 -411 -1729 -810 -99 -130 -112 -127 -165 44 -54 175 -217 511 -308 636 -64 88 -70 91 -224 117 -419 70 -947 328 -1223 597 -98 96 -153 192 -70 122 41 -35 332 -177 487 -238 97 -38 146 -55 348 -118 335 -105 983 -129 1280 -47 1070 294 1688 1238 1761 2691 16 304 7 325 -82 190 -88 -134 -504 -535 -669 -645 -618 -412 -1228 -507 -1895 -296 -192 60 -199 77 -67 163 428 277 628 871 480 1428 -20 75 -38 98 -38 48z m-682 -4962 c306 -158 601 -1396 416 -1747 -118 -224 -283 -345 -526 -387 -455 -78 -577 227 -456 1143 96 725 320 1118 566 991z m-3115 -156 c371 -172 699 -815 799 -1565 34 -251 19 -307 -108 -422 -575 -519 -1624 -162 -1931 657 -265 709 593 1630 1240 1330z m5261 -120 c20 -377 -135 -912 -290 -995 -70 -38 -72 -35 -157 230 l-64 200 -24 -90 c-50 -192 -144 -340 -215 -340 -111 0 -316 804 -228 893 53 53 200 -130 226 -283 l14 -80 36 105 c100 293 222 333 332 109 l54 -110 35 105 c89 260 271 427 281 256z m-8491 -284 l75 -230 52 160 c89 272 210 336 295 154 126 -268 210 -757 142 -825 -44 -44 -163 120 -247 340 -12 33 -19 24 -39 -50 -89 -330 -286 -346 -374 -30 l-22 80 -35 -125 c-54 -196 -223 -428 -275 -377 -37 37 -29 448 11 608 70 276 219 524 314 524 17 0 56 -87 103 -229z m4164 -2698 c137 -310 856 -372 1401 -121 175 81 194 76 89 -23 -356 -336 -878 -447 -1310 -278 -224 88 -517 339 -517 443 0 53 140 267 212 324 l58 46 14 -152 c8 -84 31 -191 53 -239z";

/// The Goblin emblem (`Goblin_Logo_2.svg`) as inline SVG paths, scaled to
/// `size` units and placed at `(x, y)` in the QR's module coordinate space.
/// The source art is a 600-unit-wide silhouette drawn in a flipped coordinate
/// space; we nest its original `translate/scale` group inside our placement
/// transform so the path data is copied verbatim (no risky hand-conversion).
/// Emits only `<path>` inside `<g>` so downstream SVG sanitizers (e.g. the
/// WooCommerce connector's `wp_kses` allow-list) pass it unchanged.
fn goblin_mark(x: f64, y: f64, size: f64) -> String {
    let scale = size / 600.0;
    format!(
        "<g transform=\"translate({x:.2} {y:.2}) scale({scale:.5})\">\
         <g transform=\"translate(0 601) scale(0.05 -0.05)\" fill=\"#000000\">\
         <path d=\"{GOBLIN_PATH_0}\"/><path d=\"{GOBLIN_PATH_1}\"/></g></g>"
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
        // The emblem is inlined as vector shapes, not an external <image> ref,
        // so the QR stays self-contained on any origin.
        assert!(marked.contains("<g transform"));
        assert!(!marked.contains("<image"));
        // The emblem sits in a circular excavation, not a rounded-rect tile.
        assert!(marked.contains("<circle"));
        assert!(!marked.contains("rx="));
        // The verbatim silhouette paths are present.
        assert!(marked.contains(GOBLIN_PATH_0));
        assert!(marked.contains(GOBLIN_PATH_1));
    }

    #[test]
    fn embeds_an_external_image_for_a_custom_href() {
        let logoed = svg("nprofile1qtest", Logo::Href("https://cdn.example/logo.svg")).unwrap();
        assert!(logoed.contains("<image"));
        assert!(logoed.contains("https://cdn.example/logo.svg"));
        // Custom images keep the rounded-rect backing.
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
