<?php
/**
 * Plugin Name: GoblinPay for WooCommerce
 * Plugin URI:  https://git.us-ea.st/GRIN/GoblinPay
 * Description: Accept Grin (GRIN / MimbleWimble) payments in WooCommerce through a self-hosted GoblinPay server. The customer pays from their Goblin Wallet by scanning an nprofile QR; payment travels as a gift-wrapped slatepack over Nostr. Works with the classic and the Blocks checkout. HPOS-compatible.
 * Version:     1.0.0
 * Author:      GoblinPay
 * License:     GPL-2.0-or-later
 * Requires PHP: 8.0
 * Requires at least: 6.0
 * WC requires at least: 8.0
 * WC tested up to: 10.8
 * Text Domain: goblinpay-woocommerce
 *
 * GoblinPay is a receive-only Grin payment server. This gateway talks to its
 * REST API directly:
 *   POST {gp_url}/invoice
 *        Authorization: Bearer <api_token>
 *        { order_ref, amount_fiat, currency, memo, match_mode, expiry_secs }
 *     -> { invoice_id, token, pay_url, nprofile, npub, qr_svg, amount, status, ... }
 * and receives payment events at /wp-json/goblinpay/v1/webhook
 * (HMAC-SHA256 over the raw body, header "X-GoblinPay-Signature: sha256=<hex>",
 *  idempotency key in "X-GoblinPay-Delivery: <event_id>").
 *
 * Refunds are NOT automated: GoblinPay is receive-only (it never sends), so a
 * refund is a manual, out-of-band Grin send by the merchant. See README.md.
 *
 * @package GoblinPayWooCommerce
 */

if (!defined('ABSPATH')) {
    exit;
}

define('GOBLINPAY_WC_VERSION', '1.0.0');
define('GOBLINPAY_WC_PLUGIN_FILE', __FILE__);
define('GOBLINPAY_WC_WH_NS', 'goblinpay/v1');    // keep stable: this is the webhook URL registered in GoblinPay
define('GOBLINPAY_WC_GATEWAY_ID', 'goblinpay');  // keep stable: ties to the saved settings option
define('GOBLINPAY_WC_EXPIRE_HOOK', 'goblinpay_wc_expire_check');
define('GOBLINPAY_WC_POLL_HOOK', 'goblinpay_wc_poll_check');

/* HPOS (custom order tables) + Cart/Checkout Blocks compatibility. */
add_action('before_woocommerce_init', function () {
    if (class_exists('\Automattic\WooCommerce\Utilities\FeaturesUtil')) {
        \Automattic\WooCommerce\Utilities\FeaturesUtil::declare_compatibility('custom_order_tables', __FILE__, true);
        \Automattic\WooCommerce\Utilities\FeaturesUtil::declare_compatibility('cart_checkout_blocks', __FILE__, true);
    }
});

/* Block checkout payment integration (Woo Blocks, merged into WC core). */
add_action('woocommerce_blocks_payment_method_type_registration', function ($registry) {
    if (class_exists('Automattic\WooCommerce\Blocks\Payments\Integrations\AbstractPaymentMethodType')) {
        require_once __DIR__ . '/includes/class-blocks.php';
        $registry->register(new GoblinPay_WC_Blocks_Support());
    }
});

/* Register the gateway. */
add_filter('woocommerce_payment_gateways', function ($gateways) {
    $gateways[] = 'WC_Gateway_GoblinPay';
    return $gateways;
});

/* Settings link on the Plugins list. */
add_filter('plugin_action_links_' . plugin_basename(__FILE__), function ($links) {
    $url = admin_url('admin.php?page=wc-settings&tab=checkout&section=' . GOBLINPAY_WC_GATEWAY_ID);
    array_unshift($links, '<a href="' . esc_url($url) . '">' . esc_html__('Settings', 'goblinpay-woocommerce') . '</a>');
    return $links;
});

add_action('plugins_loaded', function () {
    if (!class_exists('WC_Payment_Gateway')) {
        return;
    }

    class WC_Gateway_GoblinPay extends WC_Payment_Gateway {

        public function __construct() {
            $this->id                 = GOBLINPAY_WC_GATEWAY_ID;
            $this->method_title       = __('GoblinPay (Grin)', 'goblinpay-woocommerce');
            $this->method_description = __('Accept Grin (GRIN) payments through a self-hosted GoblinPay server. Customers pay from their Goblin Wallet.', 'goblinpay-woocommerce');
            $this->has_fields         = false;
            $this->supports           = array('products');

            $this->init_form_fields();
            $this->init_settings();

            $this->title       = $this->get_option('title', __('Grin (GRIN)', 'goblinpay-woocommerce'));
            $this->description = $this->get_option('description');
            $this->enabled     = $this->get_option('enabled', 'no');

            add_action('woocommerce_update_options_payment_gateways_' . $this->id, array($this, 'process_admin_options'));
            add_action('woocommerce_thankyou_' . $this->id, array($this, 'thankyou_page'));
        }

        public function init_form_fields() {
            $webhook_url = esc_html(rest_url(GOBLINPAY_WC_WH_NS . '/webhook'));
            $this->form_fields = array(
                'enabled' => array(
                    'title'   => __('Enable/Disable', 'goblinpay-woocommerce'),
                    'type'    => 'checkbox',
                    'label'   => __('Enable Grin payments via GoblinPay', 'goblinpay-woocommerce'),
                    'default' => 'no',
                ),
                'title' => array(
                    'title'       => __('Title', 'goblinpay-woocommerce'),
                    'type'        => 'text',
                    'default'     => __('Grin (GRIN)', 'goblinpay-woocommerce'),
                    'desc_tip'    => true,
                    'description' => __('Payment method title shown at checkout.', 'goblinpay-woocommerce'),
                ),
                'description' => array(
                    'title'   => __('Description', 'goblinpay-woocommerce'),
                    'type'    => 'textarea',
                    'default' => __('Pay with Grin from your Goblin Wallet. You will be shown a QR code (or redirected to a secure checkout) to complete the payment.', 'goblinpay-woocommerce'),
                ),
                'gp_url' => array(
                    'title'       => __('GoblinPay URL', 'goblinpay-woocommerce'),
                    'type'        => 'text',
                    'default'     => 'http://127.0.0.1:8192',
                    'placeholder' => 'http://127.0.0.1:8192',
                    'desc_tip'    => true,
                    'description' => __('Base URL of your GoblinPay server (no trailing slash).', 'goblinpay-woocommerce'),
                ),
                'api_token' => array(
                    'title'       => __('API Token', 'goblinpay-woocommerce'),
                    'type'        => 'password',
                    'desc_tip'    => true,
                    'description' => __('Bearer token for the GoblinPay create-invoice API (GP_API_TOKEN on the server).', 'goblinpay-woocommerce'),
                ),
                'webhook_secret' => array(
                    'title'       => __('Webhook Secret', 'goblinpay-woocommerce'),
                    'type'        => 'password',
                    'description' => sprintf(
                        /* translators: %s: webhook URL */
                        __('Shared HMAC secret (GP_WEBHOOK_SECRET on the server). Set GoblinPay\'s GP_WEBHOOK_URL to: %s', 'goblinpay-woocommerce'),
                        '<code>' . $webhook_url . '</code>'
                    ),
                ),
                'match_mode' => array(
                    'title'       => __('Matching mode', 'goblinpay-woocommerce'),
                    'type'        => 'select',
                    'default'     => 'derived',
                    'options'     => array(
                        'derived' => __('Per-invoice identity (recommended)', 'goblinpay-woocommerce'),
                        'memo'    => __('Order reference (memo)', 'goblinpay-woocommerce'),
                        'amount'  => __('Amount only', 'goblinpay-woocommerce'),
                        ''        => __('Server default', 'goblinpay-woocommerce'),
                    ),
                    'desc_tip'    => true,
                    'description' => __('How GoblinPay matches an incoming payment to this order. Per-invoice identity gives each order its own QR and is the most reliable.', 'goblinpay-woocommerce'),
                ),
                'checkout_ux' => array(
                    'title'       => __('Checkout experience', 'goblinpay-woocommerce'),
                    'type'        => 'select',
                    'default'     => 'redirect',
                    'options'     => array(
                        'redirect' => __('Redirect to the hosted GoblinPay checkout (recommended)', 'goblinpay-woocommerce'),
                        'embed'    => __('Show the QR on the order-received page', 'goblinpay-woocommerce'),
                    ),
                    'desc_tip'    => true,
                    'description' => __('Redirect sends the customer to GoblinPay\'s /pay page. Embed keeps them on your site and shows the Goblin QR on the order-received page.', 'goblinpay-woocommerce'),
                ),
                'payment_window' => array(
                    'title'       => __('Payment window (minutes)', 'goblinpay-woocommerce'),
                    'type'        => 'number',
                    'default'     => '1440',
                    'desc_tip'    => true,
                    'description' => __('If still unpaid after this many minutes, the order is cancelled. Set 0 to disable.', 'goblinpay-woocommerce'),
                ),
                'debug' => array(
                    'title'   => __('Debug logging', 'goblinpay-woocommerce'),
                    'type'    => 'checkbox',
                    'label'   => __('Log requests/webhooks (WooCommerce -> Status -> Logs, source "goblinpay")', 'goblinpay-woocommerce'),
                    'default' => 'no',
                ),
            );
        }

        private function log($msg) {
            if ('yes' === $this->get_option('debug', 'no') && function_exists('wc_get_logger')) {
                wc_get_logger()->info(is_string($msg) ? $msg : wp_json_encode($msg), array('source' => 'goblinpay'));
            }
        }

        public function process_payment($order_id) {
            $order   = wc_get_order($order_id);
            $gp_url  = rtrim((string) $this->get_option('gp_url'), '/');
            $token   = trim((string) $this->get_option('api_token'));

            if (!$order || '' === $gp_url || '' === $token) {
                wc_add_notice(__('Grin payments are not fully configured.', 'goblinpay-woocommerce'), 'error');
                return array('result' => 'failure');
            }

            $window  = (int) $this->get_option('payment_window', 1440);
            $mode    = (string) $this->get_option('match_mode', 'derived');

            $payload = array(
                'order_ref'   => (string) $order->get_id(),
                'amount_fiat' => (string) $order->get_total(),
                'currency'    => $order->get_currency(),
                'memo'        => sprintf(
                    /* translators: 1: order number, 2: site name */
                    __('Order %1$s at %2$s', 'goblinpay-woocommerce'),
                    $order->get_order_number(),
                    wp_specialchars_decode(get_bloginfo('name'), ENT_QUOTES)
                ),
            );
            if ('' !== $mode) {
                $payload['match_mode'] = $mode;
            }
            if ($window > 0) {
                $payload['expiry_secs'] = $window * 60;
            }
            $this->log(array('create_invoice' => $gp_url . '/invoice', 'payload' => $payload));

            $resp = wp_remote_post($gp_url . '/invoice', array(
                'timeout' => 30,
                'headers' => array(
                    'Content-Type'  => 'application/json',
                    'Accept'        => 'application/json',
                    'Authorization' => 'Bearer ' . $token,
                ),
                'body'    => wp_json_encode($payload),
            ));
            if (is_wp_error($resp)) {
                $this->log(array('create_invoice_error' => $resp->get_error_message()));
                wc_add_notice(__('Could not reach the GoblinPay server. Please try again.', 'goblinpay-woocommerce'), 'error');
                return array('result' => 'failure');
            }

            $code = wp_remote_retrieve_response_code($resp);
            $body = json_decode(wp_remote_retrieve_body($resp), true);
            if ($code < 200 || $code >= 300 || !is_array($body) || empty($body['invoice_id']) || empty($body['pay_url'])) {
                $err = (is_array($body) && isset($body['error'])) ? $body['error'] : ('HTTP ' . $code);
                $this->log(array('create_invoice_bad_response' => $code, 'body' => $body));
                wc_add_notice(
                    sprintf(
                        /* translators: %s: error message */
                        __('Grin payment could not be started: %s', 'goblinpay-woocommerce'),
                        esc_html((string) $err)
                    ),
                    'error'
                );
                return array('result' => 'failure');
            }

            // Persist the checkout details for the order-received page and reconciliation.
            $order->update_meta_data('_goblinpay_invoice_id', sanitize_text_field((string) $body['invoice_id']));
            $order->update_meta_data('_goblinpay_pay_url', esc_url_raw((string) $body['pay_url']));
            if (!empty($body['token'])) {
                $order->update_meta_data('_goblinpay_token', sanitize_text_field((string) $body['token']));
            }
            if (!empty($body['nprofile'])) {
                $order->update_meta_data('_goblinpay_nprofile', sanitize_text_field((string) $body['nprofile']));
            }
            if (!empty($body['amount'])) {
                $order->update_meta_data('_goblinpay_amount', sanitize_text_field((string) $body['amount']));
            }
            if (!empty($body['qr_svg'])) {
                // Sanitised on output; store the raw SVG returned by our own GoblinPay.
                $order->update_meta_data('_goblinpay_qr_svg', (string) $body['qr_svg']);
            }

            // Awaiting payment -> on-hold (reserves stock; avoids WooCommerce's
            // default unpaid-order auto-cancel that would kill slow crypto payments).
            $order->update_status('on-hold', sprintf(
                /* translators: %s: GoblinPay invoice id */
                __('Awaiting Grin payment (GoblinPay invoice %s).', 'goblinpay-woocommerce'),
                sanitize_text_field((string) $body['invoice_id'])
            ));
            $order->save();

            // Webhook-miss safety net: poll the invoice once, mid-window.
            wp_schedule_single_event(time() + 5 * MINUTE_IN_SECONDS, GOBLINPAY_WC_POLL_HOOK, array($order->get_id()));
            // Expiry fallback.
            if ($window > 0) {
                wp_schedule_single_event(time() + $window * MINUTE_IN_SECONDS, GOBLINPAY_WC_EXPIRE_HOOK, array($order->get_id()));
            }

            if (function_exists('WC') && WC()->cart) {
                WC()->cart->empty_cart();
            }

            $ux = (string) $this->get_option('checkout_ux', 'redirect');
            if ('embed' === $ux) {
                // Stay on-site; the QR renders on the order-received page.
                return array('result' => 'success', 'redirect' => $this->get_return_url($order));
            }
            return array('result' => 'success', 'redirect' => esc_url_raw((string) $body['pay_url']));
        }

        /** Render the Goblin QR + nprofile panel on the order-received page (embed UX). */
        public function thankyou_page($order_id) {
            if ('embed' !== (string) $this->get_option('checkout_ux', 'redirect')) {
                return;
            }
            $order = wc_get_order($order_id);
            if (!$order || $order->get_payment_method() !== GOBLINPAY_WC_GATEWAY_ID) {
                return;
            }
            if ($order->is_paid()) {
                echo '<section class="goblinpay-panel goblinpay-paid" style="margin:1.5em 0;max-width:420px;border:1px solid #33322a;border-radius:16px;overflow:hidden;background:#1e1e17;color:#f4f1e6;font-family:system-ui,-apple-system,\'Segoe UI\',Roboto,sans-serif">';
                echo '<div style="background:#14140f;padding:0.9em 1.1em;display:flex;align-items:center">' . goblinpay_wc_wordmark() . '</div>';
                echo '<div style="padding:1.1em 1.25em"><p style="margin:0;color:#57b894;font-weight:600">'
                    . esc_html__('Grin payment received. Thank you!', 'goblinpay-woocommerce')
                    . '</p></div></section>';
                return;
            }

            $qr       = (string) $order->get_meta('_goblinpay_qr_svg');
            $nprofile = (string) $order->get_meta('_goblinpay_nprofile');
            $pay_url  = (string) $order->get_meta('_goblinpay_pay_url');
            $amount   = (string) $order->get_meta('_goblinpay_amount');

            echo '<section class="goblinpay-panel" style="margin:1.5em 0;max-width:420px;border:1px solid #33322a;border-radius:16px;overflow:hidden;background:#1e1e17;color:#f4f1e6;font-family:system-ui,-apple-system,\'Segoe UI\',Roboto,sans-serif">';
            // Branded header bar: the GoblinPay wordmark, Apple Pay style.
            echo '<div class="goblinpay-header" style="background:#14140f;padding:0.9em 1.1em;display:flex;align-items:center">';
            echo goblinpay_wc_wordmark();
            echo '</div>';
            echo '<div class="goblinpay-body" style="padding:1.1em 1.25em 1.35em">';
            echo '<h2 style="margin:0 0 0.35em;font-size:1.2em;color:#f4f1e6">' . esc_html__('Pay with Goblin (GRIN)', 'goblinpay-woocommerce') . '</h2>';
            echo '<p style="margin:0 0 0.75em;color:#a8a294;font-size:0.92em">' . esc_html__('Scan this code with your Goblin Wallet to pay.', 'goblinpay-woocommerce') . '</p>';
            if ('' !== $amount) {
                echo '<p style="margin:0 0 0.75em;font-size:1.5em;font-weight:700;color:#e9c542">' . esc_html($amount) . '</p>';
            }
            if ('' !== $qr) {
                echo '<div class="goblinpay-qr" style="background:#fff;border-radius:14px;padding:0.75em;max-width:280px;margin:0 auto 0.75em">' . goblinpay_wc_kses_svg($qr) . '</div>';
            }
            if ('' !== $nprofile) {
                echo '<p style="word-break:break-all;font-family:ui-monospace,monospace;font-size:12px;color:#a8a294;background:#14140f;border-radius:10px;padding:0.5em 0.65em">' . esc_html($nprofile) . '</p>';
            }
            if ('' !== $pay_url) {
                echo '<p style="margin:0.75em 0 0"><a href="' . esc_url($pay_url) . '" target="_blank" rel="noopener" style="color:#e9c542;font-weight:600">'
                    . esc_html__('Open the secure GoblinPay checkout', 'goblinpay-woocommerce') . '</a></p>';
            }
            echo '<p class="goblinpay-status" style="margin:0.9em 0 0;color:#a8a294;font-size:0.85em">' . esc_html__('Waiting for payment. This page refreshes automatically.', 'goblinpay-woocommerce') . '</p>';
            echo '</div>';
            // Zero-JS live refresh while the order is unpaid (mirrors the hosted page).
            echo '<meta http-equiv="refresh" content="20">';
            echo '</section>';
        }
    }
});

/* ----------------------------------------------------------------------- *
 * Webhook receiver: POST /wp-json/goblinpay/v1/webhook
 * ----------------------------------------------------------------------- */
add_action('rest_api_init', function () {
    register_rest_route(GOBLINPAY_WC_WH_NS, '/webhook', array(
        'methods'             => 'POST',
        'permission_callback' => '__return_true', // authenticated by the HMAC signature below
        'callback'            => 'goblinpay_wc_handle_webhook',
    ));
});

function goblinpay_wc_log($m) {
    $s = get_option('woocommerce_' . GOBLINPAY_WC_GATEWAY_ID . '_settings', array());
    if (is_array($s) && !empty($s['debug']) && 'yes' === $s['debug'] && function_exists('wc_get_logger')) {
        wc_get_logger()->info(is_string($m) ? $m : wp_json_encode($m), array('source' => 'goblinpay'));
    }
}

/**
 * Handle a GoblinPay payment webhook. Verifies the HMAC over the exact raw
 * body, dedupes on the event id, maps order_ref -> WC order, and settles.
 */
function goblinpay_wc_handle_webhook(WP_REST_Request $request) {
    $settings = get_option('woocommerce_' . GOBLINPAY_WC_GATEWAY_ID . '_settings', array());
    $secret   = (is_array($settings) && isset($settings['webhook_secret'])) ? $settings['webhook_secret'] : '';

    $raw = $request->get_body();
    $sig = (string) $request->get_header('x-goblinpay-signature');

    if ('' === (string) $secret) {
        return new WP_REST_Response(array('error' => 'webhook secret not configured'), 500);
    }
    // Verify HMAC-SHA256 over the EXACT raw body bytes, constant-time compare.
    $expected = 'sha256=' . hash_hmac('sha256', $raw, (string) $secret);
    if (!hash_equals($expected, $sig)) {
        goblinpay_wc_log(array('webhook_bad_sig' => $sig));
        return new WP_REST_Response(array('error' => 'invalid signature'), 401);
    }

    $data = json_decode($raw, true);
    if (!is_array($data)) {
        return new WP_REST_Response(array('error' => 'bad payload'), 400);
    }
    goblinpay_wc_log(array('webhook' => $data));

    // Idempotency: dedupe on the event id (also carried in X-GoblinPay-Delivery).
    $event_id = isset($data['event_id']) ? (string) $data['event_id'] : (string) $request->get_header('x-goblinpay-delivery');
    if ('' !== $event_id) {
        $key = 'goblinpay_evt_' . md5($event_id);
        if (false !== get_transient($key)) {
            return new WP_REST_Response(array('ok' => true, 'dedupe' => true), 200); // already processed
        }
        set_transient($key, 1, WEEK_IN_SECONDS);
    }

    $event_type = isset($data['event_type']) ? (string) $data['event_type'] : '';
    $order_ref  = isset($data['order_ref']) ? (string) $data['order_ref'] : '';
    $invoice_id = isset($data['invoice_id']) ? (string) $data['invoice_id'] : '';
    $payment    = (isset($data['payment']) && is_array($data['payment'])) ? $data['payment'] : array();
    $slate_id   = isset($payment['slate_id']) ? (string) $payment['slate_id'] : '';

    if ('' === $order_ref) {
        return new WP_REST_Response(array('ok' => true, 'note' => 'no order_ref'), 200); // ack, nothing to do
    }
    $order = wc_get_order((int) $order_ref);
    if (!$order || $order->get_payment_method() !== GOBLINPAY_WC_GATEWAY_ID) {
        return new WP_REST_Response(array('ok' => true, 'note' => 'order not found'), 200);
    }

    // Bind the webhook to the invoice we created for this order (defence in depth).
    $known = (string) $order->get_meta('_goblinpay_invoice_id');
    if ('' !== $known && '' !== $invoice_id && !hash_equals($known, $invoice_id)) {
        goblinpay_wc_log(array('invoice_mismatch' => array('order' => $order_ref, 'known' => $known, 'got' => $invoice_id)));
        return new WP_REST_Response(array('ok' => true, 'note' => 'invoice mismatch'), 200);
    }

    switch ($event_type) {
        case 'payment.received':
            // Funds received off-chain (S2 returned). Complete the order.
            goblinpay_wc_settle_order($order, $slate_id, __('Grin payment received via GoblinPay.', 'goblinpay-woocommerce'));
            break;

        case 'payment.confirmed':
            // On-chain confirmation may arrive after payment.received. Idempotent:
            // complete if not already paid, otherwise just note the confirmation.
            if (!$order->is_paid()) {
                goblinpay_wc_settle_order($order, $slate_id, __('Grin payment confirmed on chain via GoblinPay.', 'goblinpay-woocommerce'));
            } else {
                $height = isset($payment['confirmed_height']) ? $payment['confirmed_height'] : null;
                $order->add_order_note(
                    null === $height
                        ? __('Grin payment confirmed on chain.', 'goblinpay-woocommerce')
                        : sprintf(
                            /* translators: %s: block height */
                            __('Grin payment confirmed on chain at height %s.', 'goblinpay-woocommerce'),
                            (string) $height
                        )
                );
            }
            break;

        default:
            goblinpay_wc_log(array('unhandled_event' => $event_type));
    }

    return new WP_REST_Response(array('ok' => true), 200);
}

/** Complete an order once, idempotently. */
function goblinpay_wc_settle_order($order, $slate_id, $note) {
    if ($order->is_paid()) {
        return;
    }
    $order->payment_complete('' !== (string) $slate_id ? $slate_id : '');
    $order->add_order_note($note);
}

/* Poll fallback: if a webhook was missed, ask GoblinPay for the invoice status. */
add_action(GOBLINPAY_WC_POLL_HOOK, 'goblinpay_wc_poll_invoice');
function goblinpay_wc_poll_invoice($order_id) {
    $order = wc_get_order($order_id);
    if (!$order || $order->get_payment_method() !== GOBLINPAY_WC_GATEWAY_ID || $order->is_paid()) {
        return;
    }
    $settings   = get_option('woocommerce_' . GOBLINPAY_WC_GATEWAY_ID . '_settings', array());
    $gp_url     = isset($settings['gp_url']) ? rtrim((string) $settings['gp_url'], '/') : '';
    $token      = isset($settings['api_token']) ? trim((string) $settings['api_token']) : '';
    $invoice_id = (string) $order->get_meta('_goblinpay_invoice_id');
    if ('' === $gp_url || '' === $token || '' === $invoice_id) {
        return;
    }

    $resp = wp_remote_get($gp_url . '/invoice/' . rawurlencode($invoice_id), array(
        'timeout' => 20,
        'headers' => array(
            'Accept'        => 'application/json',
            'Authorization' => 'Bearer ' . $token,
        ),
    ));
    if (is_wp_error($resp)) {
        goblinpay_wc_log(array('poll_error' => $resp->get_error_message()));
        return;
    }
    $body = json_decode(wp_remote_retrieve_body($resp), true);
    if (is_array($body) && isset($body['status']) && 'paid' === $body['status']) {
        goblinpay_wc_settle_order($order, '', __('Grin payment reconciled via GoblinPay status poll.', 'goblinpay-woocommerce'));
    }
}

/* WooCommerce-side expiry fallback (polls once more before cancelling). */
add_action(GOBLINPAY_WC_EXPIRE_HOOK, 'goblinpay_wc_maybe_expire_order');
function goblinpay_wc_maybe_expire_order($order_id) {
    goblinpay_wc_poll_invoice($order_id); // last chance to catch a missed webhook
    $order = wc_get_order($order_id);
    if (!$order || $order->get_payment_method() !== GOBLINPAY_WC_GATEWAY_ID) {
        return;
    }
    if (!$order->is_paid() && $order->has_status(array('on-hold', 'pending'))) {
        $order->update_status('cancelled', __('Grin payment window elapsed without payment.', 'goblinpay-woocommerce'));
    }
}

/**
 * The GoblinPay wordmark, Apple Pay style: a gold Goblin "P" badge next to the
 * "GoblinPay" name. Emitted as self-contained inline SVG so it renders on the
 * order-received page with no external asset request (the GoblinPay static dir
 * is not reachable from the shop's origin). Trusted, plugin-authored markup.
 */
function goblinpay_wc_wordmark() {
    return '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 168 32" height="22" role="img" aria-label="GoblinPay" style="display:block">'
        . '<g transform="translate(0 2) scale(0.4375)">'
        . '<rect width="64" height="64" rx="14" fill="#e9c542"/>'
        . '<path fill="#201d09" fill-rule="evenodd" d="M22 14H35a12 12 0 0 1 0 24H30V50H22ZM30 21H34a6 6 0 0 1 0 12H30Z"/>'
        . '</g>'
        . '<text x="38" y="23" font-family="system-ui,-apple-system,\'Segoe UI\',Roboto,sans-serif" font-size="21" font-weight="700" letter-spacing="-0.5" fill="#f4f1e6">Goblin<tspan fill="#e9c542">Pay</tspan></text>'
        . '</svg>';
}

/**
 * Sanitise a GoblinPay-generated QR SVG for safe output. Allows only the small
 * tag/attribute set the server emits (svg/g/rect/path/circle/image), so a
 * compromised or misconfigured endpoint cannot inject script into the
 * order-received page. `g`/`circle` cover the inlined center Goblin mark.
 */
function goblinpay_wc_kses_svg($svg) {
    $allowed = array(
        'svg'    => array('xmlns' => true, 'width' => true, 'height' => true, 'viewbox' => true, 'viewBox' => true, 'role' => true, 'shape-rendering' => true, 'class' => true, 'aria-label' => true),
        'g'      => array('fill' => true, 'fill-rule' => true, 'transform' => true),
        'rect'   => array('x' => true, 'y' => true, 'width' => true, 'height' => true, 'rx' => true, 'ry' => true, 'fill' => true),
        'path'   => array('d' => true, 'fill' => true, 'fill-rule' => true),
        'circle' => array('cx' => true, 'cy' => true, 'r' => true, 'fill' => true),
        'image'  => array('x' => true, 'y' => true, 'width' => true, 'height' => true, 'href' => true, 'xlink:href' => true, 'preserveaspectratio' => true),
        'title'  => array(),
    );
    return wp_kses($svg, $allowed);
}
