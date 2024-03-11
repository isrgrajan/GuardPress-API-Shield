<?php
/**
 * Plugin Name: GuardPress API Shield
 * Description: Disable XML-RPC and REST API functionalities for login, password recovery, and registration to enhance security.
 * Version: 1.0
 * Author: isrg rajan
 * Plugin URI: https://github.com/isrgrajan/GuardPress-API-Shield/
 */

class GuardPressApiShieldException extends Exception {}

// Disable XML-RPC for login, password recovery, and registration
try {
    if (version_compare(PHP_VERSION, '7.4', '<')) {
        throw new GuardPressApiShieldException('This plugin requires PHP 7.4 or later.');
    }

    if (!function_exists('guardpress_disable_xmlrpc')) {
        function guardpress_disable_xmlrpc() {
            add_filter('xmlrpc_enabled', '__return_false');
        }
        guardpress_disable_xmlrpc();
    }
} catch (GuardPressApiShieldException $e) {
    // Handle exception (e.g., log or display an error message)
    error_log('GuardPressApiShieldException: ' . $e->getMessage());
}

// Disable REST API for login, password recovery, and registration
try {
    if (version_compare(PHP_VERSION, '7.4', '<')) {
        throw new GuardPressApiShieldException('This plugin requires PHP 7.4 or later.');
    }

    if (!function_exists('guardpress_disable_rest_api')) {
        function guardpress_disable_rest_api($result) {
            // Check if the request is for the authentication route
            $rest_route = '/wp/v2/users';
            try {
                if (version_compare(PHP_VERSION, '8.3', '>=')) {
                    // Use new PHP 8.3 feature, if available
                    $uri = $_SERVER['REQUEST_URI'];
                } else {
                    // Use the old method for PHP versions prior to 8.3
                    $uri = filter_input(INPUT_SERVER, 'REQUEST_URI');
                }

                if (strpos($uri, $rest_route) !== false) {
                    throw new GuardPressApiShieldException('Access to this resource is restricted.');
                }
            } catch (GuardPressApiShieldException $e) {
                // Handle exception (e.g., log or display an error message)
                error_log('GuardPressApiShieldException: ' . $e->getMessage());
                return new WP_Error('rest_cannot_access', __('Access to this resource is restricted.'), array('status' => rest_authorization_required_code()));
            }

            return $result;
        }
        add_filter('rest_authentication_errors', 'guardpress_disable_rest_api');
    }
} catch (GuardPressApiShieldException $e) {
    // Handle exception (e.g., log or display an error message)
    error_log('GuardPressApiShieldException: ' . $e->getMessage());
}
?>
