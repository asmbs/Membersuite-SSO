<?php
/**
 * Plugin Name: Membersuite SSO
 * Description: MemberSuite reverse SSO authentication for ASMBS members and staff.
 * Version: 1.0.7
 * Author: ASMBS
 */

if (!defined('ABSPATH')) {
    exit;
}

if (file_exists(__DIR__ . '/vendor/autoload.php')) {
    require_once __DIR__ . '/vendor/autoload.php';
}

use ASMBS\SSO\SSO;
use ASMBS\SSO\Settings;
use ASMBS\SSO\Shortcodes;

add_action('plugins_loaded', function () {
    new SSO();
    new Settings();
    new Shortcodes();
});
