<?php
/*
Plugin Name: WP Simple Security
Plugin URI: https://github.com/msigley
Description: Simple Security for preventing comment spam and brute force attacks.
Version: 3.4.3
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
	private $request_ip = null;
	private $request_ip_dot_notation = '';
	private $site_root = '';
	private $script_name = '';
	private $wpdb = null;
	private $admin_access_log_table = '';
	private $blocked_table = '';

	private $blocked_timeout_in_hours = 1;
	private $bad_request_time_period_in_minutes = 30;
	private $num_bad_requests_in_time_period = 5;

	private function __construct() {
		global $wpdb;

		//Tether wpdb to property
		$this->wpdb = &$wpdb;
		$this->admin_access_log_table = $this->wpdb->prefix . 'simple_security_admin_access_log';
		$this->blocked_table = $this->wpdb->prefix . 'simple_security_blocked';

		$this->site_root = strtolower( site_url() );
		$this->site_root = substr( $this->site_root, strpos( $this->site_root, $_SERVER['SERVER_NAME'] ) + strlen( $_SERVER['SERVER_NAME'] ) );
		$this->script_name = strtolower( $_SERVER['SCRIPT_NAME'] );

		if( defined( 'SIMPLE_SECURITY_USE_TARPIT' ) )
			$this->use_tarpit = !empty( SIMPLE_SECURITY_USE_TARPIT );

		if( defined( 'SIMPLE_SECURITY_USE_IP_BLOCKER' ) )
			$this->use_ip_blocker = !empty( SIMPLE_SECURITY_USE_IP_BLOCKER );

		if( defined( 'SIMPLE_SECURITY_BLOCK_INTERNAL_IPS' ) )
			$this->block_internal_ips = !empty( SIMPLE_SECURITY_BLOCK_INTERNAL_IPS );

		if( defined( 'SIMPLE_SECURITY_PROJECT_HONEY_POT_HTTP_BL_ACCESS_KEY' ) )
			$this->http_bl_access_key = SIMPLE_SECURITY_PROJECT_HONEY_POT_HTTP_BL_ACCESS_KEY;

		if( defined( 'SIMPLE_SECURITY_PROJECT_HONEY_POT_URL' ) )
			$this->honeypot_url = SIMPLE_SECURITY_PROJECT_HONEY_POT_URL;

		if( defined( 'SIMPLE_SECURITY_LOGIN_TOKEN_NAME' ) && defined( 'SIMPLE_SECURITY_LOGIN_TOKEN_VALUE' ) 
			&& !empty( SIMPLE_SECURITY_LOGIN_TOKEN_NAME ) && !empty( SIMPLE_SECURITY_LOGIN_TOKEN_VALUE ) ) {
			$this->login_token_name = SIMPLE_SECURITY_LOGIN_TOKEN_NAME;
			$this->login_token_value = SIMPLE_SECURITY_LOGIN_TOKEN_VALUE;
		}

		$ip = $_SERVER['REMOTE_ADDR'];
		if( $this->block_internal_ips )
			$ip = (string) filter_var( $ip, FILTER_VALIDATE_IP );
		else
			$ip = (string) filter_var( $ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE );
		$this->request_ip = @inet_pton( $ip );
		$this->request_ip_dot_notation = $ip;

		if( $this->use_ip_blocker )
			$this->use_ip_blocker = !empty( $this->request_ip );

		if( $this->use_ip_blocker && defined( 'SIMPLE_SECURITY_WHITELISTED_IPS' ) && !empty( SIMPLE_SECURITY_WHITELISTED_IPS ) ) {
			$whitelisted_ips_cache_key = SIMPLE_SECURITY_WHITELISTED_IPS;
			if( is_array( $whitelisted_ips ) ) // Support serialized arrays for PHP 5.6
				$whitelisted_ips_cache_key = serialize( $whitelisted_ips );

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
				wp_cache_set( $whitelisted_ips_cache_key, $whitelisted_ips, 'simple_security_whitelisted_ips', DAY_IN_SECONDS );
			}

			// Check if request ip is whitelisted
			$request_ip_len = strlen( $this->request_ip );
			$request_ip_binary = unpack( 'H*', $this->request_ip ); // Subnet in Hex
			foreach( $request_ip_binary as $i => $h ) $request_ip_binary[$i] = base_convert($h, 16, 2); // Array of Binary
			$request_ip_binary = implode( '', $request_ip_binary ); // Subnet in Binary, only network bits
			$whitelisted = false;

			foreach( $whitelisted_ips as $whitelisted_ip ) {
				if( $request_ip_len != $whitelisted_ip['ip_len'] ) // Don't compare IPv4 to IPv6 addresses and vice versa
					continue;

				if( $this->request_ip == $whitelisted_ip['ip'] ) {
					$whitelisted = true;
					break;
				}
				
				if( !empty( $whitelisted_ip['netmask'] ) && !empty( $whitelisted_ip['subnet_binary'] )
					&& 0 === substr_compare( $request_ip_binary, $whitelisted_ip['subnet_binary'], 0, $whitelisted_ip['netmask'] ) ) {
					$whitelisted = true;
					break;
				}
			}

			if( $whitelisted ) {
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
		add_action( 'comment_form', array( $this, 'comment_form' ) );
		add_filter( 'pre_comment_on_post', array( $this, 'pre_comment_on_post' ) );
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
		} else {
			//Replace Cheatin', uh? messages with something more professional
			//Sets a new wp_die_handler
			add_filter( 'wp_die_handler', array( $this, 'wp_die_handler' ) );
			
			// Remove a tags from the tags allowed in comments
			add_action( 'init', array( $this, 'remove_bad_comment_tags' ) );
			//Remove author query vars to prevent DB enumeration
			add_filter('query_vars', array( $this, 'remove_insecure_query_vars' ) );
			//Remove Bad Comment Author URLS
			add_filter( 'get_comment_author_url', array( $this, 'comment_author_url' ) );
		}

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
	}
	
	static function &object() {
		if ( ! self::$object instanceof WPSimpleSecurity ) {
			self::$object = new WPSimpleSecurity();
		}
		return self::$object;
	}

	public function activation() {
		$this->install_tables();

		$this->delete_all_table_data();
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
		$sql = "CREATE TABLE IF NOT EXISTS `".$this->admin_access_log_table."` (
						`ip` VARBINARY(16) NOT NULL,
						`accessed` DATETIME NOT NULL,
						KEY ip (`ip`)
					) $charset_collate;";
		dbDelta($sql);

		//Create blocked table
		$sql = "CREATE TABLE IF NOT EXISTS `".$this->blocked_table."` (
						`ip` VARBINARY(16) NOT NULL,
						`risk_level` ENUM('low','medium','high') NOT NULL,
						`created` DATETIME NOT NULL,
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
		// Randomly clean table data on requests. ~%1 chance of this not happening in 25 requests.
		// Deletes expired ip blocks and old ip access log data.
		if ( !mt_rand(0, 5) )
			$this->gc_table_data();

		//Block external WP Cron requests if not using the alternate wp cron method
		if( !defined( 'ALTERNATE_WP_CRON' ) || empty( ALTERNATE_WP_CRON ) )
			$this->intercept_wp_cron_request();

		//Block all XMLRPC API requests
		$this->intercept_xmlrpc_request();

		//Prevent brute force attempts on wp-login.php
		$this->intercept_login_request();

		//Stop here if IP is blocked. This is intercepted last to allow bad requests to continue to hit the tarpit.
		if( $this->use_ip_blocker ) {
			$this->intercept_blocked_request();
			$this->intercept_non_get_request();
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
	}

	public function pre_comment_on_post( $comment_post_ID ) {
		if( !current_user_can( 'edit_posts' ) ) {
			//Prevent links in comments
			if( preg_match( '/<\s*a/i', $_POST['comment'] ) )
				wp_die('We no longer allow &lta&gt tags to be posted in our comments. Please remove your &lta&gt tag and try again.');
			
			if( false !== stripos( $_POST['comment'], '://' ) )
				wp_die('We no longer allow urls to be posted in our comments. Please remove your url and try again.');
		}

		//Prevent comment data length overflow
		if( 255 < strlen( $_POST['author'] )
			|| 100 < strlen( $_POST['email'] )
			|| 200 < strlen( $_POST['url'] )
			|| 65535 < strlen( $_POST['comment'] )
			//Verify captcha
			|| !$this->verify_hidden_math_captcha( $_POST['sec_qa'], $comment_post_ID )
			//Verify comment form nonce
			|| !$this->verify_nonce( $_POST['simple_security_comment_nonce'], 'simple_security_comment_' . $comment_post_ID ) ) {
			if( $this->use_ip_blocker )
				$this->log_request();

			if( !empty( $this->honeypot_url ) ) {
				wp_redirect( $this->honeypot_url, 307 ); // Use status 307 to encourage the bot to send the POST again for the honeypot
				die();
			}

			//Send comment flood message since its in core and will confuse and slow down bots that recognize it
			if ( defined( 'DOING_AJAX' ) )
				die( __( 'You are posting comments too quickly. Slow down.' ) );
			wp_die( __( 'You are posting comments too quickly. Slow down.' ) );
		}

		return $commentdata;
	}
	
	function wp_die_handler( $handler ) {
		return array( $this, 'action_denied_message' );
	}

	function action_denied_message( $message, $title = '', $args = array() ) {
		if( 'Cheatin&#8217; uh?' == $message )
			$message = 'Oops, so sorry! Action denied. If you feel you received this message by mistake, please contact us.';
		_default_wp_die_handler( $message, $title, $args = array() );
	}

	public function remove_insecure_query_vars( $allowed_query_vars ) {
		return array_diff( $allowed_query_vars, array( 'author' ) );
	}

	public function sanitize_thumbnail_paths( $thumbnail_data ) {
		if( isset( $thumbnail_data['thumb'] ) )
			$thumbnail_data['thumb'] = basename( $thumbnail_data['thumb'] );
		
		return $thumbnail_data;
	}

	/**
	 * WP Admin protection functions
	 */
	public function intercept_bad_admin_requests() {
		$doing_wp_ajax = defined( 'DOING_AJAX' ) && DOING_AJAX && !empty( $_REQUEST['action'] );
		if( $doing_wp_ajax || current_user_can( 'edit_posts' ) )
			return;
		
		if( $this->use_ip_blocker )
			$this->log_request();
		if( $this->use_tarpit )
			include 'includes/la_brea.php';

		wp_die( 'Access Denied', 'Access Denied', array( 'response' => 403 ) );
	}

	/**
	 * WP Cron protection functions
	 */
	private function intercept_wp_cron_request() {
		$script_name = strtolower( $_SERVER['SCRIPT_NAME'] );

		if( $this->site_root . '/wp-cron.php' === $this->script_name && !empty( $this->request_ip ) && $this->request_ip !== @inet_pton( '127.0.0.1' ) ) {
			if( $this->use_ip_blocker )
				$this->log_request();
			if( $this->use_tarpit )
				include 'includes/la_brea.php';
			
			wp_die( 'Access Denied', 'Access Denied', array( 'response' => 403 ) );
		}
	}

	/**
	 * WP API protection functions
	 */
	private function intercept_xmlrpc_request() {
		$script_name = strtolower( $_SERVER['SCRIPT_NAME'] );

		if( $this->site_root . '/xmlrpc.php' === $this->script_name ) {
			if( $this->use_ip_blocker )
				$this->log_request();
			if( $this->use_tarpit )
				include 'includes/la_brea.php';
			
			add_filter( 'wp_die_xmlrpc_handler', function( $die_handler ) { return '_default_wp_die_handler'; } );
			wp_die( 'Access Denied', 'Access Denied', array( 'response' => 403 ) );
		}
	}

	/**
	 * Login protection functions
	 */
	private function intercept_login_request() {
		if( empty( $this->login_token_name ) || empty( $this->login_token_value ) )
			return;

		if( 'POST' == $_SERVER['REQUEST_METHOD'] || $this->site_root . '/wp-login.php' !== $this->script_name )
			return;
		
		if( $_REQUEST['action'] == 'logout' || $_REQUEST['action'] == 'rp' ) {
			return;
		}

		if( !empty( $this->login_token_name ) && ( empty( $_REQUEST[$this->login_token_name] ) || $_REQUEST[$this->login_token_name] !== $this->login_token_value ) ) {
			if( $this->use_ip_blocker )
				$this->log_request();
			if( $this->use_tarpit )
				include 'includes/la_brea.php';

			wp_die( 'Access Denied', 'Access Denied', array( 'response' => 403 ) );
		}
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
		if( remove_query_arg( 'redirect_to', $_SERVER['HTTP_REFERER'] ) === wp_login_url() 
			&& $this->verify_nonce( $_REQUEST['simple_security_wp_login'], 'simple_security_wp_login' ) )
			return;

		if( $this->use_ip_blocker )
			$this->log_request();
		if( $this->use_tarpit )
			include 'includes/la_brea.php';

		wp_die( 'Access Denied', 'Access Denied', array( 'response' => 403 ) );
	}

	/**
	 * Anti Spam functions
	 */

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

	private function hidden_math_captcha_field( $action = 0 ) {
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
				document.currentScript.previousElementSibling.querySelector('input[name=sec_qa]').value = '<?php echo $captcha_value; ?>';
			</script>
			<noscript>
				Javascript is required to be enabled for the submission of this form.
			</noscript>
			<?php
			$captcha_field = ob_get_contents();
			ob_end_clean();
			wp_cache_set( $action, $captcha_field, 'simple_security_math_captcha_field', HOUR_IN_SECONDS );
		}
		echo $captcha_field;
	}

	private function verify_hidden_math_captcha( $captcha_value, $action = 0 ) {
		$action = $this->hidden_math_captcha_action( $action );
		return is_numeric( $captcha_value ) && abs( $captcha_value ) >= 18 + $action;
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
	private function intercept_non_get_request() {
		if( 'GET' === strtoupper( $_SERVER['REQUEST_METHOD'] ) )
			return;

		// Include wp_validate_redirect and wp_redirect since they aren't available yet
		require_once( ABSPATH . WPINC . '/pluggable.php' );

		if( empty( $_SERVER['HTTP_USER_AGENT'] ) 
			// Block popular headless browsers
			|| false !== stripos( $_SERVER['HTTP_USER_AGENT'], 'headlesschrome' ) // Headless Chrome
			|| false !== stripos( $_SERVER['HTTP_USER_AGENT'], 'phantomjs' ) // PhantomJS
			|| false !== stripos( $_SERVER['HTTP_USER_AGENT'], 'slimerjs' ) // SlimerJS
			|| false !== stripos( $_SERVER['HTTP_USER_AGENT'], 'splash' ) // Splash'
			// Block requests with an unsafe referer
			|| ( !empty( $_SERVER['HTTP_REFERER'] ) && !wp_validate_redirect( $_SERVER['HTTP_REFERER'], false ) )
			// Block IPs with spam reps in http:BL
			|| $this->is_spam_ip() ) {
			$this->block_ip();

			if( !empty( $this->honeypot_url ) )
				wp_redirect( $this->honeypot_url, 307 ); // Use status 307 to encourage the bot to send the POST again for the honeypot
			else
				wp_redirect( get_bloginfo( 'url' ), 303 );
			die();
		}
	}

	private function intercept_blocked_request() {
		$blocked_ip = $this->is_blocked_ip();
		if( empty( $blocked_ip ) )
			return;

		// Include wp_nonce functions and wp_redirect since they aren't available yet
		require_once( ABSPATH . WPINC . '/pluggable.php' );

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
		$now = current_time( 'mysql' );
		$query = $this->wpdb->prepare( "INSERT INTO {$this->admin_access_log_table} (ip, accessed) VALUES (%s, %s)", $this->request_ip, $now );
		$this->wpdb->query( $query );

		$query = $this->wpdb->prepare( "SELECT COUNT(1) as num_access_attempts FROM {$this->admin_access_log_table} WHERE ip=%s AND {$this->bad_request_time_period_in_minutes} >= TIMESTAMPDIFF( MINUTE, accessed, %s )", $this->request_ip, $now );
		$num_access_attempts = $this->wpdb->get_var( $query );
		if( $num_access_attempts >= $this->num_bad_requests_in_time_period )
			$this->block_ip();
	}

	private function block_ip( $risk_level = 'low' ) {
		$now = current_time( 'mysql' );
		$query = $this->wpdb->prepare( "REPLACE INTO {$this->blocked_table} (ip, risk_level, created) VALUES (%s, %s, %s)", $this->request_ip, $risk_level, $now );
		$this->wpdb->query( $query );
	}

	private function unblock_ip() {
		wp_cache_set( $this->request_ip_dot_notation, '0', 'simple_security_is_spam_ip', DAY_IN_SECONDS ); // Prevent spam ip blocks from being issued again without bad activity
		$query = $this->wpdb->prepare( "DELETE QUICK FROM {$this->blocked_table} WHERE ip=%s LIMIT 1", $this->request_ip );
		$this->wpdb->query( $query );
	}

	private function is_blocked_ip() {
		//Use HOUR units for better DB memcache support (redis)
		$now = current_time('Y-m-d H:00:00');
		$query = $this->wpdb->prepare( "SELECT INET6_NTOA(ip) as ip, risk_level, created FROM {$this->blocked_table} WHERE ip=%s AND {$this->blocked_timeout_in_hours} > TIMESTAMPDIFF( HOUR, created, '$now' ) LIMIT 1", $this->request_ip );
		$blocked = $this->wpdb->get_row( $query );
		return $blocked;
	}

	private function gc_table_data() {
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

	/**
	 * Helper functions
	 */
	private function self_uri(){
		$url = 'http';
		$script_name = '';
		if ( isset( $_SERVER['REQUEST_URI'] ) ):
			$script_name = $_SERVER['REQUEST_URI'];
		else:
			$script_name = $_SERVER['PHP_SELF'];
			if ( $_SERVER['QUERY_STRING'] > ' ' ):
				$script_name .= '?' . $_SERVER['QUERY_STRING'];
			endif;
		endif;

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
$WPSimpleSecurity->intercept_bad_requests();
