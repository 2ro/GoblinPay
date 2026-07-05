# Black GoblinPay badge: pay.html integration note

This branch (`badge-black`) adds the black GoblinPay badge, the light-surface
counterpart to the existing white wordmark. It is the mark that does the job the
black Apple Pay badge does at checkout: a compact "this payment method is
GoblinPay" lockup (goblin mark + "Pay") for light surfaces.

## What is already wired on this branch

- Asset: `static/goblinpay-badge-black.svg` (self-contained inline SVG, no
  external font: the mark reuses the wallet's goblin head geometry, "Pay" uses
  the same system font stack as the existing wordmark).
- Route: served at `/static/goblinpay-badge-black.svg`
  (`crates/gp-server/src/main.rs`, alongside the wordmark route).
- WooCommerce checkout row: the classic gateway `get_icon()` and the Blocks
  checkout label both render the badge next to the method title
  (`connectors/woocommerce/`).

So the badge asset and its serving route are ready. `pay.html` needs no code
from this branch to keep working; the snippet below is the only optional edit,
and it is intentionally left for after the grin1 rail work merges to avoid
touching a file another agent owns.

## Why the pay-page header was NOT changed

`templates/pay.html` renders the header on a dark surface and correctly uses the
**white** wordmark (`/static/goblinpay-wordmark.svg`). The black badge is a
**light-surface** asset; dropping it onto the dark header would put a black
rectangle on a dark background. So the pay page keeps the white wordmark, and
the black badge is used where a shopper picks the method on a light surface
(the WooCommerce checkout row, done on this branch).

## Optional pay.html snippet (only if a light-surface method chip is wanted)

If a light-surface "you are paying with" chip is later added to the pay page
(for example a light card summarising the method), drop the badge in with a
single self-contained `<img>`. It touches only the header block the branding
commit already added, so the conflict surface is one line.

Replace, in `templates/pay.html`, the brand link (currently):

```html
  <a class="brand" href="/"><img class="brandmark" src="/static/goblinpay-wordmark.svg" alt="GoblinPay"></a>
```

with a version that also carries the method badge (kept in the same header
block, so it will not restructure the page):

```html
  <a class="brand" href="/"><img class="brandmark" src="/static/goblinpay-wordmark.svg" alt="GoblinPay"></a>
  <img class="method-badge" src="/static/goblinpay-badge-black.svg" alt="Pay with GoblinPay" height="28">
```

Then, if a light backing is desired behind the badge, add to `static/style.css`:

```css
.method-badge { display: inline-block; vertical-align: middle; }
```

No template logic, no new variables: the badge is a static asset served by the
route already added on this branch.
