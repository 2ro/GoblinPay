<?php
/**
 * WooCommerce Blocks payment-method integration for the GoblinPay gateway.
 *
 * @package GoblinPayWooCommerce
 */

if (!defined('ABSPATH')) {
    exit;
}

use Automattic\WooCommerce\Blocks\Payments\Integrations\AbstractPaymentMethodType;

final class GoblinPay_WC_Blocks_Support extends AbstractPaymentMethodType {

    protected $name = 'goblinpay';

    /** @var array Named to avoid clashing with the parent's protected $settings. */
    private $gw_settings = array();

    public function initialize() {
        $this->gw_settings = get_option('woocommerce_goblinpay_settings', array());
        if (!is_array($this->gw_settings)) {
            $this->gw_settings = array();
        }
    }

    public function is_active() {
        return !empty($this->gw_settings['enabled']) && 'yes' === $this->gw_settings['enabled'];
    }

    public function get_payment_method_script_handles() {
        $handle = 'goblinpay-blocks';
        wp_register_script(
            $handle,
            plugins_url('assets/js/blocks.js', GOBLINPAY_WC_PLUGIN_FILE),
            array('wc-blocks-registry', 'wc-settings', 'wp-element', 'wp-html-entities'),
            GOBLINPAY_WC_VERSION,
            true
        );
        return array($handle);
    }

    public function get_payment_method_data() {
        return array(
            'title'       => !empty($this->gw_settings['title']) ? $this->gw_settings['title'] : 'Grin (GRIN)',
            'description' => isset($this->gw_settings['description']) ? $this->gw_settings['description'] : '',
            'supports'    => array('products'),
        );
    }
}
