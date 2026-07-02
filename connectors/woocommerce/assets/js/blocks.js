/* global window */
/**
 * WooCommerce Blocks (Checkout/Cart block) integration for the GoblinPay
 * payment gateway. No build step: uses the globals WooCommerce Blocks exposes
 * (wc-blocks-registry, wc-settings, wp-element, wp-html-entities). This is a
 * redirect/on-site gateway: the block submits to the Store API, which runs the
 * server-side process_payment() and follows the returned redirect (to the
 * hosted GoblinPay /pay page, or the order-received page for the embedded QR).
 */
( function () {
	'use strict';

	if ( ! window.wc || ! window.wc.wcBlocksRegistry || ! window.wp || ! window.wp.element ) {
		return;
	}

	var registerPaymentMethod = window.wc.wcBlocksRegistry.registerPaymentMethod;
	var getSetting = window.wc.wcSettings.getSetting;
	var createElement = window.wp.element.createElement;
	var decodeEntities = ( window.wp.htmlEntities && window.wp.htmlEntities.decodeEntities ) || function ( s ) { return s; };

	var data = getSetting( 'goblinpay_data', {} );
	var title = decodeEntities( data.title || 'Pay with Grin (GRIN)' );
	var description = decodeEntities( data.description || '' );

	var Content = function () {
		return createElement( 'div', { className: 'goblinpay-blocks-description' }, description );
	};

	registerPaymentMethod( {
		name: 'goblinpay',
		label: createElement( 'span', null, title ),
		content: createElement( Content, null ),
		edit: createElement( Content, null ),
		canMakePayment: function () { return true; },
		ariaLabel: title,
		supports: {
			features: data.supports || [ 'products' ],
		},
	} );
} )();
