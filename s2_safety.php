<?php 
/*
Plugin Name: s2 safety functions
Plugin URI:
Description: Secure your wordpress website with a single plugin, no setup check on https://securityheaders.com/
Version: 1.9.2
Author: Sebas2
Author URI: http://s2.sebas2.nl
License: GNU GPL
Tested on https://securityheaders.com/
*/
 
// Start the plugin
add_action(
    'plugins_loaded',
    [ s2_safety::get_instance(), 'plugin_setup' ]
);
  
class s2_safety {

    # Singleton
    protected static $instance = NULL;

    private $options;

    # Leave empty
    public function __construct() {}

    # Singleton
    public static function get_instance()
    {
        NULL === self::$instance and self::$instance = new self;
        return self::$instance;
    }
    # Start our action hooks
    public function plugin_setup() {
        add_action( 'send_headers', array( $this, 's2_setsafety_headers' ) );
    }

    public function s2_setsafety_headers() {

        // Set the validity of the header, 6 months is a good starting point.
        $ageInSeconds = 31536000;
        // Render the header.
        header( 'Strict-Transport-Security: max-age=' . $ageInSeconds . '; includeSubDomains;' );
        // Header set X-XSS-Protection "1; mode=block"
        header("X-XSS-Protection: 1; mode=block");
        // prevents the browser from doing MIME-type sniffing
        header('X-Content-Type-Options: nosniff');
        // The browser will only set the referrer header on requests to the same origin. 
        // If the destination is another origin then no referrer information will be sent
        header('Referrer-Policy: same-origin');
        // Content Security Policy (CSP) header not implemented
        header("Content-Security-Policy: default-src 'none';");
        header("Content-Security-Policy: script-src 'unsafe-inline';");
        header("Content-Security-Policy: style-src 'unsafe-inline';");
        header("Content-Security-Policy: base-uri 'self';");
        header("Content-Security-Policy: frame-ancestors 'none';");
        header("Content-Security-Policy: object-src 'self';");
        /*
            Clickjacking is one of the malicious attacks used against people on the web. 
            Back in 2009 Microsoft came out with a new measure in IE8 to fight against clickjacking that’s 
            since been adopted by Firefox, Chrome, Safari, Opera, and others. This is through servers 
            setting a http header of X-Frame-Options and browsers following the settings.
        */
        header('X-Frame-Options: SAMEORIGIN');
        /*
            Will be removed
         */
        header("Feature-Policy: geolocation 'self';");
        header("Feature-Policy: camera 'none';");
        header("Feature-Policy: unsized-media 'none';");
        /*
            Since 1.9.1  Feature-Policy migration to Permissions-Policy
         */        
        header("Permissions-Policy: fullscreen=(), geolocation=(), camera=();");
    }
}
