<?php
/*
Plugin Name: WP Simple Security
Plugin URI: https://github.com/msigley
Description: Simple Security for preventing comment spam and brute force attacks.
Version: 3.9.0
Author: Matthew Sigley
License: GPL2
*/

class WPSimpleSecurity {
	private static $object = null;
	private $css_js_version = '1';
	private $use_tarpit = false;
	private $use_ip_blocker = false;
	private $block_internal_ips = false;
	private $http_bl_access_key = '';
	private $honeypot_url = null;
	private $login_token_name = null;
	private $login_token_value = null;
	private $enforce_whitelist_admin_access = false;
	private $cloudflare_turnstile_sitekey = '';
	private $cloudflare_turnstile_secretkey = '';
	private $cloudflare_turnstile_js_enqueued = false;
	private $cloudflare_turnstile_last_validated_response = '';

	private $request_ip = null;
	private $request_ip_dot_notation = '';
	private $whitelisted = false;
	private $site_root = '';
	private $script_name = '';
	private $wpdb = null;
	private $admin_access_log_table = '';
	private $blocked_table = '';

	private $blocked_timeout_in_hours = 1;
	private $bad_request_time_period_in_minutes = 30;
	private $num_bad_requests_in_time_period = 4;

	// Nice reference for most important requests to block:
	// https://github.com/wargio/naxsi/blob/main/naxsi_rules/naxsi_core.rules
	
	// Alot of the files and folders below aren't part of wordpress, but they are included here to catch bad traffic.
	private $restricted_requests = array(
		'/wp-cron.php*', // WP Cron
		'/xmlrpc.php*', // XMLRPC API
		'*/etc/passwd', // Unix password file
		'*/etc/shells', // Unix login shells
		'/webdav/*', // Default webdav folder
		'/WEB-INF/*', // Java Servlet config folder
		'*.sqlite', '*.sqlite.gz', '*.sql', '*.sql.gz', '.mdb', // Common database file types
		'/cgi-bin/*', '*.cgi', // Common Gateway Interface files
	);

	private $restricted_query_vars = array(
		'author', // User enumeration
	);

	private $restricted_values = array(
		// \\\\ is one \
		'\.\.(\/|\\\\)', // Directory traversal
		'c:\\\\',
		'cmd\.exe',
		'<(script|meta)', // XXS
		'javascript:',
		'\/\*|\*\/|--|@@', // SQL Injection
		'select|union|update|delete|insert|replace|table|dumpfile', 
		'(?<!http|https):\/\/', // Remote file inclusion
	);

	private $restricted_comment_countries = array(
		'NG' => 'NG' // Nigeria
	);

	private function __construct() {
		global $wpdb;

		//Tether wpdb to property
		$this->wpdb = &$wpdb;
		$this->admin_access_log_table = $this->wpdb->prefix . 'simple_security_admin_access_log';
		$this->blocked_table = $this->wpdb->prefix . 'simple_security_blocked';

		$this->script_name = parse_url( $_SERVER['REQUEST_URI'], PHP_URL_PATH );
		$this->site_root = (string) parse_url( untrailingslashit( site_url() ), PHP_URL_PATH );
		if( !empty( $site_root ) )
			$this->script_name = substr( $script_name, strlen( $site_root ) );

		if( defined( 'SIMPLE_SECURITY_USE_TARPIT' ) )
			$this->use_tarpit = !empty( SIMPLE_SECURITY_USE_TARPIT );

		if( defined( 'SIMPLE_SECURITY_USE_IP_BLOCKER' ) )
			$this->use_ip_blocker = !empty( SIMPLE_SECURITY_USE_IP_BLOCKER );

		if( defined( 'SIMPLE_SECURITY_BLOCK_INTERNAL_IPS' ) )
			$this->block_internal_ips = !empty( SIMPLE_SECURITY_BLOCK_INTERNAL_IPS );

		if( defined( 'SIMPLE_SECURITY_ENFORCE_WHITELIST_ADMIN_ACCESS' ) )
			$this->enforce_whitelist_admin_access = !empty( SIMPLE_SECURITY_ENFORCE_WHITELIST_ADMIN_ACCESS );	

		if( defined( 'SIMPLE_SECURITY_PROJECT_HONEY_POT_HTTP_BL_ACCESS_KEY' ) )
			$this->http_bl_access_key = SIMPLE_SECURITY_PROJECT_HONEY_POT_HTTP_BL_ACCESS_KEY;

		if( defined( 'SIMPLE_SECURITY_PROJECT_HONEY_POT_URL' ) )
			$this->honeypot_url = SIMPLE_SECURITY_PROJECT_HONEY_POT_URL;

		if( defined( 'SIMPLE_SECURITY_LOGIN_TOKEN_NAME' ) && defined( 'SIMPLE_SECURITY_LOGIN_TOKEN_VALUE' ) 
			&& !empty( SIMPLE_SECURITY_LOGIN_TOKEN_NAME ) && !empty( SIMPLE_SECURITY_LOGIN_TOKEN_VALUE ) ) {
			$this->login_token_name = SIMPLE_SECURITY_LOGIN_TOKEN_NAME;
			$this->login_token_value = SIMPLE_SECURITY_LOGIN_TOKEN_VALUE;
		}

		if( defined( 'SIMPLE_SECURITY_CLOUDFLARE_TURNSTILE_SITEKEY' ) && defined( 'SIMPLE_SECURITY_CLOUDFLARE_TURNSTILE_SECRETKEY' ) ) {
			$this->cloudflare_turnstile_sitekey = SIMPLE_SECURITY_CLOUDFLARE_TURNSTILE_SITEKEY;
			$this->cloudflare_turnstile_secretkey = SIMPLE_SECURITY_CLOUDFLARE_TURNSTILE_SECRETKEY;
		}

		$ip = (string) filter_var( $_SERVER['REMOTE_ADDR'], FILTER_VALIDATE_IP );
		$this->request_ip_dot_notation = $ip;
		if( !$this->block_internal_ips )
			$ip = (string) filter_var( $ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE );
		$this->request_ip = @inet_pton( $ip );

		if( $this->use_ip_blocker )
			$this->use_ip_blocker = !empty( $this->request_ip );

		if( !$this->block_internal_ips )
			$this->whitelisted = empty( $this->request_ip );

		if( !$this->whitelisted && $this->use_ip_blocker && defined( 'SIMPLE_SECURITY_WHITELISTED_IPS' ) && !empty( SIMPLE_SECURITY_WHITELISTED_IPS ) ) {
			$whitelisted_ips_cache_key = SIMPLE_SECURITY_WHITELISTED_IPS;
			if( is_array( $whitelisted_ips_cache_key ) ) // Support serialized arrays for PHP 5.6
				$whitelisted_ips_cache_key = serialize( $whitelisted_ips );
			$whitelisted_ips_cache_key = md5( $whitelisted_ips_cache_key );

			// Try to pull the whitelisted ips array from the cache to avoid building it on every request
			$whitelisted_ips = wp_cache_get( $whitelisted_ips_cache_key, 'simple_security_whitelisted_ips' );
			if( false === $whitelisted_ips ) {
				// Build whitelisted ips array
				$whitelisted_ips = SIMPLE_SECURITY_WHITELISTED_IPS;
				if( !is_array( $whitelisted_ips ) )
					$whitelisted_ips = unserialize( $whitelisted_ips );
				
				foreach( $whitelisted_ips as &$whitelisted_ip ) {
					$slash_pos = strrpos( $whitelisted_ip, '/' );
					$netmask = false;
					if( false !== $slash_pos ) {
						$netmask = (int) substr( $whitelisted_ip, $slash_pos + 1 );
						$whitelisted_ip = substr( $whitelisted_ip, 0, $slash_pos );
					}

					$ip = @inet_pton( $whitelisted_ip );
					if( empty($ip) )
						continue;
					
					$ip_len = strlen( $ip );

					$whitelisted_ip = array(
						'ip' => $ip,
						'ip_len' => $ip_len
					);

					if( false !== $netmask ) {
						// Convert subnet to binary string of $bits length
						$subnet_binary = unpack( 'H*', $ip ); // Subnet in Hex
						foreach( $subnet_binary as $i => $h ) $subnet_binary[$i] = base_convert($h, 16, 2); // Array of Binary
						$subnet_binary = implode( '', $subnet_binary ); // Subnet in Binary
						
						$whitelisted_ip['subnet_binary'] = $subnet_binary;
						$whitelisted_ip['netmask'] = $netmask;
					}
				}
				wp_cache_set( $whitelisted_ips_cache_key, $whitelisted_ips, 'simple_security_whitelisted_ips', WEEK_IN_SECONDS );
			}

			// Check if request ip is whitelisted
			$request_ip_len = strlen( $this->request_ip );
			$request_ip_binary = unpack( 'H*', $this->request_ip ); // Subnet in Hex
			foreach( $request_ip_binary as $i => $h ) $request_ip_binary[$i] = base_convert($h, 16, 2); // Array of Binary
			$request_ip_binary = implode( '', $request_ip_binary ); // Subnet in Binary, only network bits

			foreach( $whitelisted_ips as $whitelisted_ip ) {
				if( $request_ip_len != $whitelisted_ip['ip_len'] ) // Don't compare IPv4 to IPv6 addresses and vice versa
					continue;

				if( $this->request_ip == $whitelisted_ip['ip'] ) {
					$this->whitelisted = true;
					break;
				}
				
				if( !empty( $whitelisted_ip['netmask'] ) && !empty( $whitelisted_ip['subnet_binary'] )
					&& 0 === substr_compare( $request_ip_binary, $whitelisted_ip['subnet_binary'], 0, $whitelisted_ip['netmask'] ) ) {
					$this->whitelisted = true;
					break;
				}
			}

			if( $this->whitelisted ) {
				$this->use_tarpit = false;
				$this->use_ip_blocker = false;
			}
		}

		if( defined( 'CSSJSVERSION' ) && !empty( CSSJSVERSION ) )
			$this->css_js_version = CSSJSVERSION;
		else
			$this->css_js_version = date( 'Y-W', current_time('timestamp') );
		
		//Plugin activation
		register_activation_hook( __FILE__, array( $this, 'activation' ) );
		register_deactivation_hook( __FILE__, array( $this, 'deactivation' ) );

		//General protections
		//Remove insecure http headers
		add_filter( 'wp_headers', array( $this, 'remove_insecure_http_headers' ) );
		//Removes the WordPress version from the header for security
		add_filter( 'the_generator', array( $this, 'wb_remove_version' ) );
		//Remove XMLRPC API meta tag from head
		remove_action( 'wp_head', 'rsd_link' );
		//Removes the Windows Live Writer Manifest from the head
		remove_action( 'wp_head', 'wlwmanifest_link' );
		//Completely Disable Trackbacks
		add_filter( 'pings_open', array( $this, 'disable_all_trackbacks' ), 10, 2 );
		//Removes Trackbacks from the comment count
		add_filter( 'get_comments_number', array( $this, 'comment_count' ), 0 );
		//Prevents bad comment content
		add_action( 'comment_form', array( $this, 'comment_form' ), 999 );
		add_filter( 'pre_comment_on_post', array( $this, 'pre_comment_on_post' ) );
		//Only add hyperlinks to admin comments
		remove_filter( 'comment_text', 'make_clickable', 9 );
		add_filter( 'comment_text', array( $this, 'make_clickable' ), 9, 2 );
		//Removes insecure information on dependancy includes
		add_action( 'wp_print_scripts', array( $this, 'sanitize_scripts' ), 9999 );
		add_action( 'wp_print_styles', array( $this, 'sanitize_styles' ), 9999 );
		//Prevents arbitrary file deletion attack through post thumbnail meta
		add_filter( 'wp_update_attachment_metadata', array( $this, 'sanitize_thumbnail_paths' ) );

		//Tracking protections
		//The fact this tracking can't be disabled by the end user is ridiculously unethical.
		//To make matters worse, this tracking is only able to be disabled by exploiting the transient API instead of a 'allow_tracking' filter.
		//Prevents browser tracking by Automatic
		//See wp_check_browser_version()
		if ( !empty( $_SERVER['HTTP_USER_AGENT'] ) )
			add_filter( 'pre_site_transient_browser_' . md5( $_SERVER['HTTP_USER_AGENT'] ), '__return_null', 9999 );

		//Prevents php version tracking by Automatic
		//See wp_check_php_version()
		add_filter( 'pre_site_transient_php_check_' . md5( phpversion() ), '__return_null', 9999 );

		if( is_admin() ) {
			add_action( 'init', array( $this, 'intercept_bad_admin_requests' ), 1 ); // Delayed to init to allow user capability check
			add_action( 'admin_init', array( $this, 'admin_init' ) );
			add_action( 'admin_menu', array( $this, 'setup_admin_pages' ) );
		} else {
			//Replace Cheatin', uh? messages with something more professional
			//Sets a new wp_die_handler
			add_filter( 'wp_die_handler', array( $this, 'wp_die_handler' ) );
			
			// Remove a tags from the tags allowed in comments
			add_action( 'init', array( $this, 'remove_bad_comment_tags' ) );
			//Remove author query vars to prevent DB enumeration
			add_filter( 'query_vars', array( $this, 'remove_insecure_query_vars' ) );
			//Remove Bad Comment Author URLS
			add_filter( 'get_comment_author_url', array( $this, 'comment_author_url' ) );
			//Enforce exact query slug matches
			add_filter( 'sanitize_title', array( $this, 'sanitize_title' ), 9999, 3 );
		}

		//$_POST, $_GET, $_REQUEST Protections
		add_action( 'plugins_loaded', array( $this, 'intercept_bad_requests' ), 1 ); // Delayed to plugins_loaded to allow user capability check

		//Login form protections
		//TODO: Test for compatiblity with WooCommerce login form
		//Force logout redirects to home page
		add_filter( 'logout_url', array( $this, 'force_redirect_to_home' ) );
		//Add nonce checking to wp-login.php forms
		add_action( 'login_form', array( $this, 'add_login_form_nonce' ) );
		add_action( 'register_form', array( $this, 'add_login_form_nonce' ) );
		if( 'POST' == $_SERVER['REQUEST_METHOD'] ) {
			//Verify nonce and http referer
			add_action( 'login_form_login', array( $this, 'verify_login_form_post' ) );
			add_action( 'login_form_register', array( $this, 'verify_login_form_post' ) );
			//Removes detailed login error information for security and enforces login token
			add_filter( 'authenticate', array( $this, 'hide_login_errors' ), 10, 3 );
			add_action( 'wp_login_failed', array( $this, 'hide_login_errors' ) );
		}

		if( !empty( $this->login_token_name ) && !empty( $this->login_token_value ) ) {
			//Append login token to lostpassword_url
			add_filter( 'login_url', array( $this, 'add_login_token_to_url' ) );
			add_filter( 'lostpassword_url', array( $this, 'add_login_token_to_url' ) );
		}

		//Cron
		add_action( 'WPSimpleSecurity_gc_table_data', array( $this, 'gc_table_data' ) );
	}
	
	static function &object() {
		if ( ! self::$object instanceof WPSimpleSecurity ) {
			self::$object = new WPSimpleSecurity();
		}
		return self::$object;
	}

	public function activation() {
		$this->install_tables();

		if( !wp_next_scheduled( 'WPSimpleSecurity_gc_table_data' ) ) {
			$start_of_the_hour = time();
			$start_of_the_hour -= $start_of_the_hour % 3600;
			wp_schedule_event( $start_of_the_hour, 'hourly', 'WPSimpleSecurity_gc_table_data' );
		}
	}

	public function deactivation() {
		//$this->delete_all_table_data();
		wp_cache_flush();
		wp_clear_scheduled_hook( 'WPSimpleSecurity_gc_table_data' );
	}
	
	private function install_tables() {
		require( ABSPATH . 'wp-admin/includes/upgrade.php' ); 
		
		//Wordpress's defined charset
		$charset_collate = '';
		if ( ! empty( $this->wpdb->charset ) ) {
			$charset_collate = "DEFAULT CHARACTER SET ".$this->wpdb->charset;
			if ( ! empty( $this->wpdb->collate ) )
				$charset_collate .= " COLLATE ".$this->wpdb->collate;
		}

		//Create access log table
		$sql = "CREATE TABLE `".$this->admin_access_log_table."` (
				`ip` VARBINARY(16) NOT NULL,
				`accessed` DATETIME NOT NULL,
				`user_agent` VARCHAR(255) NULL DEFAULT(NULL),
				`url` VARCHAR(2048) NULL DEFAULT(NULL),
				`post_data` BLOB NULL DEFAULT(NULL),
				PRIMARY KEY (`ip`),
				KEY ip_accessed (`ip`,`accessed`)
			) $charset_collate;";
		dbDelta($sql);

		//Create blocked table
		$sql = "CREATE TABLE `".$this->blocked_table."` (
				`ip` VARBINARY(16) NOT NULL,
				`risk_level` ENUM('low','medium','high') NOT NULL,
				`created` DATETIME NOT NULL,
				`user_agent` VARCHAR(255) NULL DEFAULT(NULL),
				`language` VARCHAR(128) NULL DEFAULT(NULL),
				PRIMARY KEY (`ip`)
			) $charset_collate;";
		dbDelta($sql);
	}

	private function delete_all_table_data() {
		$query = "TRUNCATE TABLE `".$this->admin_access_log_table."`";
		$result = $this->wpdb->query($query);

		$query = "TRUNCATE TABLE `".$this->blocked_table."`";
		$result = $this->wpdb->query($query);
	}
	
	public function intercept_bad_requests() {
		// Stop here if IP is blocked
		$this->intercept_blocked_request();

		// Block external restricted requests
		$this->intercept_restricted_requests();

		// Block external restricted requests with bad values
		$this->intercept_restricted_values();

		// Prevent brute force attempts on wp-login.php
		$this->intercept_login_request();

		// Check non-get requests for spam bot identifiers and block them
		$this->intercept_non_get_request();

		// Stop here if IP has been blocked from this request
		$this->intercept_blocked_request();
	}

	public function deny_request() {
		$this->log_request();
		$this->block_ip_from_access_attempts();
		if( $this->use_tarpit )
			include 'includes/la_brea.php';

		wp_die( 'Access Denied', 'Access Denied', array( 'response' => 403 ) );
	}

	public function send_to_honeypot() {
		if( empty( $this->honeypot_url ) )
			return;

		if( filter_var( $this->honeypot_url, FILTER_VALIDATE_URL ) ) {
			wp_redirect( $this->honeypot_url, 307 ); // Use status 307 to encourage the bot to send the POST again for the honeypot
			die();
		} elseif( substr( $this->honeypot_url, 0, 1 ) === '/' ) {
			$_SERVER['REQUEST_URI'] = $this->honeypot_url;
			$_SERVER['SCRIPT_NAME'] = $this->honeypot_url;
			$_SERVER['PHP_SELF'] = $this->honeypot_url;
			include( $this->honeypot_url );
			die();
		}
	}

	/**
	 * General protection functions
	 */
	public function sanitize_scripts() {
		global $wp_scripts, $ShoppScripts;
		
		foreach( $wp_scripts->queue as $enqueued_script ) {
			$wp_scripts->registered[$enqueued_script]->ver = $this->css_js_version;
		}

		if( !empty( $ShoppScripts->registered ) ) {
			foreach( $ShoppScripts->queue as $enqueued_script ) {
				$ShoppScripts->registered[$enqueued_script]->ver = $this->css_js_version;
			}
		}
	}
	
	public function sanitize_styles() {
		global $wp_styles;
		
		foreach( $wp_styles->queue as $enqueued_style ) {
			$wp_styles->registered[$enqueued_style]->ver = $this->css_js_version;
		}
	}
	
	public function remove_insecure_http_headers( $headers ) {
		unset( $headers['X-Pingback'] );

		return $headers;
	}

	public function wb_remove_version() {
		return '';
	}
	
	public function disable_all_trackbacks($open, $post_id) {
		return false;
	}

	public function remove_bad_comment_tags() {
		global $allowedtags;

		if( !current_user_can( 'edit_posts' ) )
			unset( $allowedtags['a'] );
	}

	public function comment_count( $count ) {
		if ( ! is_admin() ) {
			global $id;
			$comments_by_type = &separate_comments( get_comments( 'status=approve&post_id=' . $id ) );
			return count( $comments_by_type['comment'] );
		} else {
			return $count;
		}
	}

	public function comment_author_url( $url ) {
		list( $protocol, $uri ) = explode( '://', $url, 2 );
		
		//Only allow http or https urls in comments
		if( $protocol != 'http' && $protocol != 'https' )
			return '';
		
		list( $host, $domain ) = explode( '.', $uri, 2 );
		
		//Check for valid domain period syntax
		if( strlen( $domain ) < 2
			|| $domain != trim( $domain, " \t\n\r\0\x0B." ) )
			return '';
		
		//Reject urls with user credentials or on custom ports
		if( strpos( $host, ':' ) !== false 
			|| strpos( $host, '@' ) !== false )
			return '';
		
		return $url;
	}

	public function comment_form( $post_id ) {
		$this->hidden_math_captcha_field( $post_id );
		$this->nonce_field( 'simple_security_comment_' . $post_id, 'simple_security_comment_nonce' );
		$this->cloudflare_captcha_field();
	}

	public function pre_comment_on_post( $comment_post_ID ) {
		$comment_author = ( isset( $_POST['author'] ) )  ? trim( $_POST['author'] ) : '';
		$comment_author_email = ( isset( $_POST['email'] ) )   ? trim( $_POST['email'] ) : '';
		$comment_author_url = ( isset( $_POST['url'] ) )     ? trim( $_POST['url'] ) : '';
		$comment_content = ( isset( $_POST['comment'] ) ) ? trim( $_POST['comment'] ) : '';
		$comment_sec_qa	= ( isset( $_POST['comment'] ) ) ? $_POST['sec_qa'] : '';	

		if( !current_user_can( 'edit_posts' ) ) {
			// Prevent links in comments
			if( preg_match( '/<\s*a/i', $comment_content ) )
				wp_die( 'We no longer allow &lta&gt tags to be posted in our comments. Please remove your &lta&gt tag(s) and try again.' );
			
			if( false !== stripos( $comment_content, '://' ) )
				wp_die( 'We no longer allow urls to be posted in our comments. Please remove the url(s) from your comment and try again.' );
			// Prevent emails in comments
			if( preg_match( '/(?<=(?:[.0-9a-z_+-]))@(?:(?:[0-9a-z-]+\.)+[0-9a-z]{2,})/i', $comment_content ) )
				wp_die( 'We no longer allow email addresses to be posted in our comments. Please remove your email address(es) from your comment and try again.' );
		}

		// Prevent comment data length overflow
		if( 255 < strlen( $comment_author )
			|| 100 < strlen( $comment_author_email )
			|| 200 < strlen( $comment_author_url )
			|| 65535 < strlen( $comment_content )
			// Verify captcha
			|| !$this->verify_hidden_math_captcha( $comment_sec_qa, $comment_post_ID )
			|| !$this->verify_cloudflare_captcha_field()
			// Verify comment form nonce
			|| !$this->verify_nonce( $_POST['simple_security_comment_nonce'], 'simple_security_comment_' . $comment_post_ID )
			// Check geoip country
			|| class_exists( 'IP2Location' ) && isset( $this->restricted_comment_countries[ (string) IP2Location::get_country_short( $this->request_ip_dot_notation ) ] )
			// Check comment content for spam
			|| $this->comment_content_spam_check( $comment_author, $comment_author_email, $comment_author_url, $comment_content )
			) {
			
			$this->log_request();
			$this->block_ip_from_access_attempts();
			$this->send_to_honeypot();

			// Fallback if not using honeypot.
			// Send comment flood message since its in core and will confuse and slow down bots that recognize it
			if ( defined( 'DOING_AJAX' ) )
				die( __( 'You are posting comments too quickly. Slow down.' ) );
			wp_die( __( 'You are posting comments too quickly. Slow down.' ), '', array( 'response' => 429 ) );
		}

		return $commentdata;
	}

	private function comment_content_spam_check( $comment_author, $comment_author_email, $comment_author_url, $comment_content ) {
		$regex_keys = trim( get_option('WPSimpleSecurity_disallowed_regex') );
		if ( '' == $regex_keys )
			return false; // If regex keys are empty

		$regex_keys = explode("\n", $regex_keys );
		foreach( $regex_keys as &$regex ) {
			$regex = trim( $regex );
			$regex = chr(1) . "\b$regex\b" . chr(1) . "ui";
			if( @preg_match($regex, $comment_author) || @preg_match($regex, $comment_content) )
				return true;

			unset( $regex );
		}

		return false;
	}

	public function make_clickable( $comment_text, $comment = false ) {
		if( false === $comment )
			return $comment_text;

		if( $comment->user_id ) {
			if( user_can( $comment->user_id, 'edit_posts' ) )
				$comment_text = make_clickable( $comment_text );
		}
		return $comment_text;
	}
	
	public function wp_die_handler( $handler ) {
		return array( $this, 'action_denied_message' );
	}

	public function action_denied_message( $message, $title = '', $args = array() ) {
		if( 'Cheatin&#8217; uh?' == $message )
			$message = 'Oops, so sorry! Action denied. If you feel you received this message by mistake, please contact us.';
		_default_wp_die_handler( $message, $title, $args );
	}

	public function remove_insecure_query_vars( $allowed_query_vars ) {
		return array_diff( $allowed_query_vars, $this->restricted_query_vars ); 
	}

	public function sanitize_thumbnail_paths( $thumbnail_data ) {
		if( isset( $thumbnail_data['thumb'] ) )
			$thumbnail_data['thumb'] = basename( $thumbnail_data['thumb'] );
		
		return $thumbnail_data;
	}

	public function sanitize_title( $title, $raw_title, $context ) {
		if( 'query' === $context )
			return $raw_title;
		return $title;
	}

	/**
	 * $_POST, $_GET, $_REQUEST Protections
	 */
	public function intercept_restricted_values() {
		if( ( !$this->block_internal_ips && $this->request_ip_dot_notation === '127.0.0.1' ) //Don't block requests from localhost
			|| current_user_can( 'unfiltered_html' ) )
			return;

		$num_restricted_values = count( $this->restricted_values );
		for( $i = 0; $i < $num_restricted_values; $i++ ) {
			foreach( $_REQUEST as &$value ) {
				if( preg_match( "\2" . $this->restricted_values[$i] . "\2ui", $value ) ) {
					add_filter( 'wp_die_xmlrpc_handler', function( $die_handler ) { return '_default_wp_die_handler'; } );
	
					$this->deny_request();
				}
			}
			unset( $value );
		}
	}

	/**
	 * WP Admin protection functions
	 */
	public function intercept_bad_admin_requests() {
		if( ( defined( 'DOING_AJAX' ) && DOING_AJAX && !empty( $_REQUEST['action'] ) ) )
			return;

		$is_admin_user = current_user_can( 'edit_posts' );
		if( $this->enforce_whitelist_admin_access && $this->whitelisted && $is_admin_user
			|| !$this->enforce_whitelist_admin_access && $is_admin_user )
			return;
		
		$this->deny_request();
	}

	/**
	 * Restricted request protection functions
	 */
	private function intercept_restricted_requests() {
		if( !$this->block_internal_ips && $this->request_ip_dot_notation === '127.0.0.1' )
			return; //Don't block requests from localhost
		
		$num_restricted_requests = count( $this->restricted_requests );
		for( $i = 0; $i < $num_restricted_requests; $i++ ) {
			if( fnmatch( $this->restricted_requests[$i], $this->script_name, FNM_NOESCAPE | FNM_CASEFOLD ) ) {
				add_filter( 'wp_die_xmlrpc_handler', function( $die_handler ) { return '_default_wp_die_handler'; } );

				$this->deny_request();
			}
		}

		$num_restricted_query_vars = count( $this->restricted_query_vars );
		for( $i = 0; $i < $num_restricted_query_vars; $i++ ) {
			if( isset( $_GET[ $this->restricted_query_vars[$i] ] ) ) {
				add_filter( 'wp_die_xmlrpc_handler', function( $die_handler ) { return '_default_wp_die_handler'; } );

				$this->deny_request();
			}
		}

		foreach( $_GET as $name => $value ) {
			// Block requests with BIGINTs in the query string as it is obvious cache poisoning or log evasion
			// SHA1 hashes are 40 characters in length, so we are only blocking INTs larger than that
			if( preg_match( '/[0-9]{40,}/u', $name ) 
				|| preg_match( '/[0-9]{40,}/u', $value ) ) {
				add_filter( 'wp_die_xmlrpc_handler', function( $die_handler ) { return '_default_wp_die_handler'; } );

				$this->deny_request();
			}
		}
		unset( $name, $value );
	}

	/**
	 * Login protection functions
	 */
	private function intercept_login_request() {
		if( 'POST' == $_SERVER['REQUEST_METHOD'] || '/wp-login.php' !== $this->script_name )
			return;
		
		if( $_REQUEST['action'] == 'logout' || $_REQUEST['action'] == 'rp' ) {
			return;
		}

		if( $this->enforce_whitelist_admin_access && !$this->whitelisted )
			$this->deny_request();

		if( empty( $this->login_token_name ) || empty( $this->login_token_value ) )
			return;

		if( !empty( $this->login_token_name ) && ( empty( $_REQUEST[$this->login_token_name] ) || $_REQUEST[$this->login_token_name] !== $this->login_token_value ) )
			$this->deny_request();
	}

	public function add_login_token_to_url( $url ) {
		if( is_admin() ) //Don't add security token to auth_redirects
			return $url;
		return add_query_arg( $this->login_token_name, $this->login_token_value, $url );
	}

	public function force_redirect_to_home( $logout_url ) {
		$logout_url = remove_query_arg( 'redirect_to', $logout_url );
		$logout_url = add_query_arg( 'redirect_to', urlencode( get_bloginfo( 'url' ) ), $logout_url );
		return $logout_url;
	}

	public function hide_login_errors( $null=null, $username='', $password='' ) {
		if( remove_query_arg( 'redirect_to', $_SERVER['HTTP_REFERER'] ) !== wp_login_url() )
			return; //Do nothing for plugin login handlers
		
		if( empty( $username ) || empty( $password ) ) {
			$login_url = wp_login_url();
			if( !empty( $_REQUEST['redirect_to'] ) )
				$login_url = add_query_arg( 'redirect_to', urlencode( $login_url ), $login_url );
			wp_redirect( wp_login_url() );
		}
	}

	public function add_login_form_nonce() {
		$this->nonce_field( 'simple_security_wp_login', 'simple_security_wp_login' );
	}

	public function verify_login_form_post() {
		if( $this->enforce_whitelist_admin_access && !$this->whitelisted )
			$this->deny_request();

		if( remove_query_arg( 'redirect_to', $_SERVER['HTTP_REFERER'] ) === wp_login_url() 
			&& $this->verify_nonce( $_REQUEST['simple_security_wp_login'], 'simple_security_wp_login' ) )
			return;

		$this->deny_request();
	}

	/**
	 * Anti Spam functions
	 */
	private function intercept_non_get_request() {
		$request_method = strtoupper( $_SERVER['REQUEST_METHOD'] );
		if( 'GET' === $request_method || 'HEAD' === $request_method )
			return;

		// Detect headless browsers
		// Some techniques adapted from:
		// https://github.com/infosimples/detect-headless/blob/master/scripts/detect_headless.js
		/*
		$locale = !empty( $_SERVER['HTTP_ACCEPT_LANGUAGE'] );
		if( $locale && function_exists( 'locale_accept_from_http' ) )
			$locale = @locale_accept_from_http( $_SERVER['HTTP_ACCEPT_LANGUAGE'] );
		*/

		if( // Every reputable browser sends a user agent
			empty( $_SERVER['HTTP_USER_AGENT'] ) 
			// Block popular headless browsers
			|| false !== stripos( $_SERVER['HTTP_USER_AGENT'], 'headless' ) // Headless browsers
			|| false !== stripos( $_SERVER['HTTP_USER_AGENT'], 'phantomjs' ) // PhantomJS
			|| false !== stripos( $_SERVER['HTTP_USER_AGENT'], 'slimerjs' ) // SlimerJS
			|| false !== stripos( $_SERVER['HTTP_USER_AGENT'], 'splash' ) // Splash
			// Headless browsers may not send a valid Accept-Language header
			//|| false === $locale
			) {

			$this->log_request();
			$this->block_ip();
			$this->send_to_honeypot();
	
			// Fallback if not using honeypot.
			wp_redirect( get_bloginfo( 'url' ), 303 );
			die();
		}

		// Block IPs with spam reps in http:BL
		// Only check use_ip_blocker here to save the is_spam_ip() call
		if( $this->use_ip_blocker && $this->is_spam_ip() )
			$this->block_ip();
	}

	/**
	 * Look up request IP with the http:BL DNS service
	 * https://www.projecthoneypot.org/httpbl_api.php
	 */
	private function is_spam_ip() {
		if( empty( $this->http_bl_access_key ) )
			return false;

		$is_spam = wp_cache_get( $this->request_ip_dot_notation, 'simple_security_is_spam_ip' );
		if( false !== $is_spam )
			return !empty( $is_spam );

		$ip_parts = explode( '.', $this->request_ip_dot_notation );
		if( count( $ip_parts ) !== 4 )
			return false;

		$reversed_ip = implode( '.', array_reverse( $ip_parts ) );
		$http_bl_response = dns_get_record( "{$this->http_bl_access_key}.$reversed_ip.dnsbl.httpbl.org.", DNS_A );

		// Use strings to store boolean value since false is used to indicate no value exists in the cache
		$is_spam = '0'; // NXDOMAIN means IP is not in the DB
		if( !empty( $http_bl_response ) ) {
			$http_bl_response = explode( '.', $http_bl_response[0]['ip'] );
			if( count( $http_bl_response ) !== 4 ) // Bad or malformed response
				$is_spam = '0';
			else if( $http_bl_response[0] != 127 ) // First octet is the error code. 127 is a good lookup.
				$is_spam = '0';
			else if( $http_bl_response[3] == 0 ) // Forth octet is the type of visitor. 0 is search engine. 1 is suspicious.
				$is_spam = '0'; // Search engines are never blocked. This includes Cloudflare WARP traffic.
			else if( $http_bl_response[1] > 6 ) // Second octet is the number of days since last activity.
				$is_spam = '0';
			else if( $http_bl_response[2] >= 25 ) // Third octet is the treat score. A score of 25 is equivelent to sending 100 spam emails to a honeypot in one day.
				$is_spam = '1';
			else if( $http_bl_response[3] > 1 ) // Forth octet is the type of visitor. 0 is search engine. 1 is suspicious.
				$is_spam = '1';
		}

		wp_cache_set( $this->request_ip_dot_notation, $is_spam, 'simple_security_is_spam_ip', DAY_IN_SECONDS );

		return !empty( $is_spam );
	}

	public function hidden_math_captcha_field( $action = 0 ) {
		$captcha_field = wp_cache_get( $action, 'simple_security_math_captcha_field' );
		if( empty( $captcha_field ) ) {
			$field_action = $this->hidden_math_captcha_action( $action );

			$captcha_value = mt_rand( 1, 9 ) + 18 + $field_action;
			if( mt_rand( 0, 1 ) )
				$captcha_value *= -1;

			ob_start();
			// Setting the value via javascript forces javascript to be enabled for form submission
			?>
			<div style="position: absolute; clip: rect(0px 1px 1px 0px);">
				<label for="sec_qa">What is <?php echo mt_rand( 1, 9 ); ?> <?php echo ( mt_rand( 0, 1) ? '+' : '-' ); ?> <?php echo mt_rand( 1, 9 ); ?>?</label>
				<input name="sec_qa" type="text" autocomplete="security_question_answer" value="" tabindex="-1" />
			</div>
			<script type="text/javascript">
				var sec_qa = document.currentScript.previousElementSibling.querySelector('input[name=sec_qa]');
				if( sec_qa ) {
					sec_qa.value = '<?php echo $captcha_value; ?>';
					sec_qa.defaultValue = '<?php echo $captcha_value; ?>';
				}
			</script>
			<noscript>
				Javascript is required to be enabled for the submission of this form.
			</noscript>
			<?php
			$captcha_field = ob_get_contents();
			ob_end_clean();
			wp_cache_set( $action, $captcha_field, 'simple_security_math_captcha_field', 2 * MINUTE_IN_SECONDS );
		}
		echo $captcha_field;
	}

	public function cloudflare_captcha_field() {
		if( empty( $this->cloudflare_turnstile_sitekey ) || empty( $this->cloudflare_turnstile_secretkey ) )
			return;
		?>
		<div class="cf-turnstile" data-sitekey="<?php echo $this->cloudflare_turnstile_sitekey; ?>" data-execution="execute"></div>
		<?php
		if( $this->cloudflare_turnstile_js_enqueued === false ) {
			$this->cloudflare_turnstile_js_enqueued = true;
			add_action( 'wp_print_footer_scripts', function() {
				?>
				<script type="text/javascript">
					var loadCloudflareTurnstile = function() {
						let script = document.createElement('script');
						script.async = true;
						script.src = 'https://challenges.cloudflare.com/turnstile/v0/api.js';
						document.body.append(script);
					};

					if( 'loading' === document.readyState )
						window.addEventListener( 'DOMContentLoaded', loadCloudflareTurnstile );
					else
						loadCloudflareTurnstile();

					window.addEventListener( 'load', function() {
						let observer = new IntersectionObserver( function( entries, observer ) {
							for( let entry of entries ) {
								if( entry.target.offsetParent === null )
									continue;
								
								turnstile.execute( entry.target );
								observer.unobserve( entry.target );
							}
						} );
						for( let element of document.querySelectorAll('.cf-turnstile') ) {
							observer.observe( element );
						}
					} );
				</script>
				<?php
			} );
		}
	}

	public function get_cloudflare_captcha_field() {
		ob_start();
		$this->cloudflare_captcha_field();
		$output = ob_get_contents();
		ob_end_clean();
		return $output;
	}

	public function verify_cloudflare_captcha_field() {
		if( empty( $this->cloudflare_turnstile_sitekey ) || empty( $this->cloudflare_turnstile_secretkey ) )
			return true;

		if( $this->cloudflare_turnstile_last_validated_response === $_POST['cf-turnstile-response'] )
			return true;
		
		$response = wp_remote_post( 'https://challenges.cloudflare.com/turnstile/v0/siteverify', 
			array( 
				'body' => array( 
					'secret' => $this->cloudflare_turnstile_secretkey,
					'response' => $_POST['cf-turnstile-response']
				)
			)
		);

		if( !is_wp_error( $response ) && 200 === wp_remote_retrieve_response_code( $response ) ) {
			$response_body = @json_decode( wp_remote_retrieve_body( $response ) );
			if( !empty( $response_body ) && !empty( $response_body->success ) ) {
				$this->cloudflare_turnstile_last_validated_response = $_POST['cf-turnstile-response'];
				return true;
			}
		}

		return false;
	}

	public function verify_hidden_math_captcha( $captcha_value, $action = 0 ) {
		$action = $this->hidden_math_captcha_action( $action );
		return is_numeric( $captcha_value ) && abs( $captcha_value ) >= 18 + 1 + $action && abs( $captcha_value ) <= 18 + 9 + $action;
	}

	// Action generation is for obfuscation not security
	private function hidden_math_captcha_action( $action ) {
		if( !is_numeric( $action ) ) {
			$action = (string)$action;
			$action = substr( $action, -1 );
			$action = ord( $action );
		}
		return $action %= 10;
	}

	/**
	 * Nonce functions
	 */
	private function nonce_field( $action = -1, $name = "_nonce", $echo = true ) {
		$name = esc_attr( $name );
		$nonce_field = '<input type="hidden" id="' . $name . '" name="' . $name . '" value="' . $this->create_nonce( $action ) . '" />';

		if ( $echo )
			echo $nonce_field;

		return $nonce_field;
	}

	private function verify_nonce( $nonce, $action = -1 ) {
		$nonce = (string) $nonce;
		
		$i = wp_nonce_tick();

		// Nonce generated 0-12 hours ago
		if ( substr(wp_hash($i . '|' . $action, 'nonce'), -12, 10) == $nonce )
			return 1;
		// Nonce generated 12-24 hours ago
		if ( substr(wp_hash(($i - 1) . '|' . $action, 'nonce'), -12, 10) == $nonce )
			return 2;
		// Invalid nonce
		return false;
	}

	private function create_nonce( $action = -1 ) {
		$i = wp_nonce_tick();

		return substr(wp_hash($i . '|' . $action, 'nonce'), -12, 10);
	}

	/**
	 * Bad IP protection functions
	 */
	public function intercept_blocked_request() {
		if( !$this->use_ip_blocker )
			return;

		$blocked_ip = $this->is_blocked_ip();
		if( empty( $blocked_ip ) )
			return;

		$nonce_action = 'simple_security_unblock_ip|' . $blocked_ip->ip . '|' . $blocked_ip->created;
		$unblock_url = remove_query_arg( 'unblock_ip', $this->self_uri() );
		
		// Handle unblock IP requests
		if( !empty( $_REQUEST['unblock_ip'] ) ) {
			if( $this->verify_nonce( $_REQUEST['unblock_ip'], $nonce_action ) )
				$this->unblock_ip();
			else
				$this->block_ip( 'medium' ); // Failed attempt to unblock IP, raise risk level and renew block
			
			wp_redirect( $unblock_url, 303 );
			die();
		}
		
		$message = 'Your IP address (' . $blocked_ip->ip . ') has been blocked from accessing this website due to suspicous activity.';

		// Allow low risk IPs to unblock themselves
		if( 'low' == $blocked_ip->risk_level ) {
			// Obfuscate good unblock link with hidden links with identical text
			$good_link_num = mt_rand(2, 11);
			for( $i = 1; $i <= 12; $i++ ) {
				$link_nonce_action = $nonce_action;
				if( $good_link_num != $i )
					$link_nonce_action .= $i;
				$link_url = add_query_arg( 'unblock_ip', urlencode( $this->create_nonce( $link_nonce_action ) ), $unblock_url );
				$link_url = htmlentities( $link_url, ENT_QUOTES | ENT_DISALLOWED, "UTF-8" );;
				$message .= '<a class="unblock-link" href="' . $link_url . '" style="display: none;">Please unblock my IP address</a>';
			}
			$good_link_num_obf = mt_rand(12, 24);
			$child_selector = $good_link_num_obf . 'n-' . ( $good_link_num_obf - $good_link_num );
			$message .= '<style>.unblock-link:nth-child(' . $child_selector . ') { display: block !important; }</style>';
		}
		
		wp_die( $message, 'IP Blocked', array( 'response' => 403 ) );
	}

	/**
	 * IP logging functions
	 */
	private function log_request() {
		if( !$this->use_ip_blocker )
			return;

		$now = current_time( 'mysql' );
		
		$post_data = '';
		if( 'POST' === strtoupper( $_SERVER['REQUEST_METHOD'] ) )
			$post_data = @serialize( $_POST );
		$user_agent = '';
		if( !empty( $_SERVER['HTTP_USER_AGENT'] ) )
			$user_agent = $_SERVER['HTTP_USER_AGENT'];

		$query = $this->wpdb->prepare( "INSERT INTO {$this->admin_access_log_table} (ip, accessed, url, post_data, user_agent) VALUES (%s, %s, %s, %s, %s)", $this->request_ip, $now, $this->self_uri(), $post_data, $user_agent );
		$this->wpdb->query( $query );
	}

	private function block_ip_from_access_attempts() {
		if( !$this->use_ip_blocker )
			return;

		$now = current_time( 'mysql' );
		$query = $this->wpdb->prepare( "SELECT COUNT(1) as num_access_attempts FROM {$this->admin_access_log_table} WHERE ip=%s AND {$this->bad_request_time_period_in_minutes} >= TIMESTAMPDIFF( MINUTE, accessed, %s )", $this->request_ip, $now );
		$num_access_attempts = $this->wpdb->get_var( $query );
		if( $num_access_attempts >= $this->num_bad_requests_in_time_period )
			$this->block_ip();
	}

	private function block_ip( $risk_level = 'low' ) {
		if( !$this->use_ip_blocker )
			return;

		$now = current_time( 'mysql' );
		$user_agent = '';
		if( !empty( $_SERVER['HTTP_USER_AGENT'] ) )
			$user_agent = $_SERVER['HTTP_USER_AGENT'];
		$locale = !empty( $_SERVER['HTTP_ACCEPT_LANGUAGE'] );
		if( $locale && function_exists( 'locale_accept_from_http' ) )
			$locale = @locale_accept_from_http( $_SERVER['HTTP_ACCEPT_LANGUAGE'] );
		$query = $this->wpdb->prepare( "REPLACE INTO {$this->blocked_table} (ip, risk_level, created, user_agent, locale) VALUES (%s, %s, %s, %s, %s)", $this->request_ip, $risk_level, $now, $user_agent, $locale );
		$this->wpdb->query( $query );
	}

	private function unblock_ip() {
		if( !$this->use_ip_blocker )
			return;
		
		// Prevent spam ip blocks from being issued again without bad activity
		wp_cache_set( $this->request_ip_dot_notation, '0', 'simple_security_is_spam_ip', DAY_IN_SECONDS );
		// Prevent blocking again for 1 hour. Shared IPv4 used from mobile networks make this required.
		wp_cache_set( $this->request_ip_dot_notation, '0', 'simple_security_is_blocked_ip', HOUR_IN_SECONDS );
		$query = $this->wpdb->prepare( "DELETE QUICK FROM {$this->blocked_table} WHERE ip=%s LIMIT 1", $this->request_ip );
		$this->wpdb->query( $query );
	}

	private function is_blocked_ip() {
		$is_blocked = wp_cache_get( $this->request_ip_dot_notation, 'simple_security_is_blocked_ip' );
		if( false !== $is_blocked )
			return !empty( $is_blocked );

		//Use HOUR units for better DB memcache support (redis)
		$now = current_time('Y-m-d H:00:00');
		$query = $this->wpdb->prepare( "SELECT INET6_NTOA(ip) as ip, risk_level, created FROM {$this->blocked_table} WHERE ip=%s AND {$this->blocked_timeout_in_hours} > TIMESTAMPDIFF( HOUR, created, '$now' ) LIMIT 1", $this->request_ip );
		$blocked = $this->wpdb->get_row( $query );
		return $blocked;
	}

	public function get_blocked_ips() {
		$now = current_time('Y-m-d H:00:00');
		$blocked_ips = $this->wpdb->get_results( "SELECT INET6_NTOA(ip) as ip, risk_level, created,  user_agent, locale, {$this->blocked_timeout_in_hours} > TIMESTAMPDIFF( HOUR, created, '$now' ) as active FROM {$this->blocked_table} ORDER BY created DESC" );
		return $blocked_ips;
	}

	public function get_logged_ips() {
		$logged_ips = $this->wpdb->get_results( "SELECT INET6_NTOA(ip) as ip, accessed, url, post_data, user_agent FROM {$this->admin_access_log_table} ORDER BY accessed DESC" );
		return $logged_ips;
	}

	public function gc_table_data() {
		//Maintain logs for 7 days
		//Use DAY units for better DB memcache support (redis)
		$now = current_time('Y-m-d 23:59:59');

		// Use DELETE QUICK for faster MyISAM (Aria) performance.
		// Skips the repacking of the table that normally occurs.
		// Since I/O on the admin access log and blocked tables are high, the file sizes don't really matter.

		// Delete expired ip blocks.
		$num_to_clean = $this->wpdb->get_var( "SELECT COUNT(1) as num_to_clean FROM {$this->blocked_table} WHERE 7 < TIMESTAMPDIFF( DAY, created, '$now' )" );
		if ( !empty( $num_to_clean ) ) {
			$num_to_clean = (int)( $num_to_clean / 4 ); // Only DELETE 25% at a time.
			if( $num_to_clean < 50 ) //Enforce minimum LIMIT for faster clean up
				$num_to_clean = 50;
			
			$this->wpdb->query( "DELETE QUICK FROM {$this->blocked_table} WHERE 7 < TIMESTAMPDIFF( DAY, created, '$now' ) LIMIT $num_to_clean" );
		}

		// Delete old admin access log data
		$num_to_clean = $this->wpdb->get_var( "SELECT COUNT(1) as num_to_clean FROM {$this->admin_access_log_table} WHERE 7 < TIMESTAMPDIFF( DAY, accessed, '$now' )" );
		if ( !empty( $num_to_clean ) ) {
			$num_to_clean = (int)( $num_to_clean / 4 ); // Only DELETE 25% at a time.
			if( $num_to_clean < 50 ) //Enforce minimum LIMIT for faster clean up
				$num_to_clean = 50;
			
			$this->wpdb->query( "DELETE QUICK FROM {$this->admin_access_log_table} WHERE 7 <= TIMESTAMPDIFF( DAY, accessed, '$now' ) LIMIT $num_to_clean" );
		}
	}

	/*
	 * Admin functions
	 */
	public function admin_init() {
		register_setting( 'discussion', 'WPSimpleSecurity_disallowed_regex' );
		add_settings_field( 'WPSimpleSecurity_disallowed_regex', 'Comment Disallowed Regex Words', function() {
			?>
			<p><label for="WPSimpleSecurity_disallowed_regex">When a comment matches the regex in its content or name, it will be rejected. The commenter will be sent to the honeypot (if enabled). One word or phrase per line<br />
				Example of how regex is applied: <code>/\b&lt;word or phrase&gt;\b/ui</code></label></p>
			<p>
			<textarea name="WPSimpleSecurity_disallowed_regex" rows="10" cols="50" id="WPSimpleSecurity_disallowed_regex" class="large-text code"><?php echo esc_textarea( get_option( 'WPSimpleSecurity_disallowed_regex' ) ); ?></textarea>
			</p>
			<?php
		}, 'discussion' );
	}

	public function setup_admin_pages() {
		add_menu_page( 'IP Blocking', 'IP Blocking', 'manage_options', 'wp_simple_security_ipblocking', array( $this, 'admin_page' ) /*, plugins_url( '/images/firebase-logo.png' , __FILE__ )*/ );
	}

	public function admin_page() {
		?>
		<div class="wrap">
			<h2>IP Blocking Log</h2>
			<table class="wp-list-table widefat fixed">
				<thead>
					<tr>
						<th>IP Address</th>
						<th>Look Up On</th>
						<th>Risk Level</th>
						<th>Blocked on</th>
						<th>Browser Details</th>
						<th></th>
					</tr>
				</thead>
				<tbody>
					<?php
					$blocked_ips = $this->get_blocked_ips();
					foreach( $blocked_ips as $blocked_ip ) {
						?>
						<tr>
							<td><?php echo $blocked_ip->ip; ?></td>
							<td><a href="https://search.arin.net/rdap/?query=<?php echo urlencode( $blocked_ip->ip ); ?>" target="_blank">ARIN</a>&nbsp;|&nbsp;
								<a href="https://apps.db.ripe.net/db-web-ui/query?searchtext=<?php echo urlencode( $blocked_ip->ip ); ?>" target="_blank">RIPE</a>&nbsp;|&nbsp;
								<a href="https://www.projecthoneypot.org/ip_<?php echo urlencode( $blocked_ip->ip ); ?>" target="_blank">Project Honey Pot</a></td>
							<td><?php echo $blocked_ip->risk_level; ?></td>
							<td><?php echo $blocked_ip->created; ?></td>
							<td>
								<?php
								if( !empty( $blocked_ip->user_agent ) || !empty( $blocked_ip->locale ) ):
									?>
									<dialog>
										<p>User Agent:<br /><code><?php echo $blocked_ip->user_agent; ?></code></p>
										<p>Locale:<br /><code><?php echo $blocked_ip->locale; ?></code></p>
										<button onclick="this.parentElement.close();">Close</button>
									</dialog>
									<a onclick="this.previousElementSibling.showModal();">View Browser Details</a>
									<?php
								endif;
								?>
							</td>
							<td><?php echo $blocked_ip->active ? 'ACTIVE' : 'EXPIRED'; ?></td>
						</tr>
						<?
					}
					unset( $blocked_ips, $blocked_ip );
					?>
				</tbody>
			</table>
			<h2>IP Bad Request Log</h2>
			<table class="wp-list-table widefat fixed">
				<thead>
					<tr>
						<th>IP Address</th>
						<th>Look Up On</th>
						<th>URL</th>
						<th>Blocked Access At</th>
						<th>Browser Details</th>
						<th>Post Data</th>
					</tr>
				</thead>
				<tbody>
					<?php
					$logged_ips = $this->get_logged_ips();
					foreach( $logged_ips as $logged_ip ) {
						?>
						<tr>
							<td><?php echo $logged_ip->ip; ?></td>
							<td><a href="https://search.arin.net/rdap/?query=<?php echo urlencode( $logged_ip->ip ); ?>" target="_blank">ARIN</a>&nbsp;|&nbsp;
								<a href="https://apps.db.ripe.net/db-web-ui/query?searchtext=<?php echo urlencode( $logged_ip->ip ); ?>" target="_blank">RIPE</a>&nbsp;|&nbsp;
								<a href="https://www.projecthoneypot.org/ip_<?php echo urlencode( $logged_ip->ip ); ?>" target="_blank">Project Honey Pot</a></td>
							<td><?php echo htmlentities( $logged_ip->url ); ?></td>
							<td><?php echo $logged_ip->accessed; ?></td>
							<td>
								<?php
								if( !empty( $logged_ip->user_agent ) ):
									?>
									<dialog>
										<p>User Agent:<br /><code><?php echo $blocked_ip->user_agent; ?></code></p>
										<button onclick="this.parentElement.close();">Close</button>
									</dialog>
									<a onclick="this.previousElementSibling.showModal();">View Browser Details</a>
									<?php
								endif;
								?>
							</td>
							<td>
								<?php 
								$logged_ip->post_data = @unserialize( $logged_ip->post_data );
								if( !empty( $logged_ip->post_data ) ):
									?>
									<dialog><pre><?php var_dump( $logged_ip->post_data ); ?></pre><button onclick="this.parentElement.close();">Close</button></dialog>
									<a onclick="this.previousElementSibling.showModal();">View Post Data</a>
									<?php
								endif;
								?>
							</td>
						</tr>
						<?
					}
					unset( $logged_ips, $logged_ip );
					?>
				</tbody>
			</table>
		</div>
		<?php
	}

	/**
	 * Helper functions
	 */
	private function self_uri(){
		$url = 'http';
		$script_name = $_SERVER['REQUEST_URI'];

		if ( ( isset( $_SERVER['HTTPS'] ) && $_SERVER['HTTPS'] == 'on' ) || $_SERVER['SERVER_PORT'] == '443' )
			$url .= 's';

		$url .= '://';
		if ( $_SERVER['SERVER_PORT'] != '80' && $_SERVER['SERVER_PORT'] != '443' ):
			$url .= $_SERVER['HTTP_HOST'] . ':' . $_SERVER['SERVER_PORT'] . $script_name;
		else:
			$url .= $_SERVER['HTTP_HOST'] . $script_name;
		endif;

		return $url;
	}
}

$WPSimpleSecurity = WPSimpleSecurity::object();
