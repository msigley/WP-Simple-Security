<?php
/*
Plugin Name: WP Simple Security
Plugin URI: https://github.com/msigley
Description: Simple Security for preventing comment spam and brute force attacks.
Version: 3.0.0
Author: Matthew Sigley
License: GPL2
*/

class WPSimpleSecurity {
	private static $object = null;
	private $css_js_version = '1';
	private $use_tarpit = false;
	private $use_ip_blocker = false;
	private $block_internal_ips = false;
	private $login_token_name = null;
	private $login_token_value = null;
	private $site_root = '';
	private $script_name = '';
	private $wpdb = null;
	private $admin_access_log_table = '';
	private $blocked_table = '';

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

		if( defined( 'SIMPLE_SECURITY_LOGIN_TOKEN_NAME' ) && defined( 'SIMPLE_SECURITY_LOGIN_TOKEN_VALUE' ) 
			&& !empty( SIMPLE_SECURITY_LOGIN_TOKEN_NAME ) && !empty( SIMPLE_SECURITY_LOGIN_TOKEN_VALUE ) ) {
			$this->login_token_name = SIMPLE_SECURITY_LOGIN_TOKEN_NAME;
			$this->login_token_value = SIMPLE_SECURITY_LOGIN_TOKEN_VALUE;
		}

		if( defined('CSSJSVERSION') && !empty( CSSJSVERSION ) )
			$this->css_js_version = CSSJSVERSION;
		else
			$this->css_js_version = date( 'Y-W', current_time('timestamp') );
		
		//Plugin activation
		register_activation_hook( __FILE__, array( $this, 'activation' ) );

		//General protections
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
		//Limits the length of all fields from a comment form
		add_filter( 'preprocess_comment', array( $this, 'limit_comment_field_length' ) );
		//Removes insecure information on dependancy includes
		add_action( 'wp_print_scripts', array( $this, 'sanitize_scripts' ), 9999 );
		add_action( 'wp_print_styles', array( $this, 'sanitize_styles' ), 9999 );
		//Prevents arbitrary file deletion attack through post thumbnail meta
		add_filter( 'wp_update_attachment_metadata', array( $this, 'sanitize_thumbnail_paths' ) );

		if( !is_admin() ) {
			//Replace Cheatin', uh? messages with something more professional
			//Sets a new wp_die_handler
			add_filter( 'wp_die_handler', array( $this, 'wp_die_handler' ) );
			
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
						`id` bigint(20) unsigned NOT NULL auto_increment,
						`ip` VARBINARY(16) NOT NULL,
						`accessed` DATETIME NOT NULL,
						PRIMARY KEY (`id`),
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

		//Block all XMLRPC API requests
		$this->intercept_xmlrpc_request();

		//Prevent brute force attempts on wp-login.php
		$this->intercept_login_request();

		//Stop here if IP is blocked. This is intercepted last to allow bad requests to continue to hit the tarpit.
		if( $this->use_ip_blocker )
			$this->intercept_blocked_request();
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
	
	public function wb_remove_version() {
		return '';
	}
	
	public function disable_all_trackbacks($open, $post_id) {
		return false;
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

	public function limit_comment_field_length( $commentdata ) {
		$data_lengths = array_map( 'mb_strlen', $commentdata );
		$bad_length = false;
		if( 255 < $data_lengths['comment_author'] )
			$bad_length = true;
		elseif( 100 < $data_lengths['comment_author_email'] )
			$bad_length = true;
		elseif( 200 < $data_lengths['comment_author_url'] )
			$bad_length = true;
		elseif( 65535 < $data_lengths['comment_content'] )
			$bad_length = true;
			
		if( $bad_length ) {
			//Send comment flood message since its in core and will confuse and slow down bots that recognize it
			if ( defined( 'DOING_AJAX' ) )
				die( __( 'You are posting comments too quickly.  Slow down.' ) );
			wp_die( __( 'You are posting comments too quickly.  Slow down.' ) );
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

		if( empty( $_REQUEST[$this->login_token_name] ) || $_REQUEST[$this->login_token_name] !== $this->login_token_value ) {
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
	private function intercept_blocked_request() {
		$blocked_ip = $this->is_blocked_ip();
		if( empty( $blocked_ip ) )
			return;
		
		// Include wp_nonce functions since they aren't available yet
		require( ABSPATH . WPINC . '/pluggable.php' );

		$request_ip = $this->get_request_ip();
		$nonce_action = 'simple_security_unblock_ip|' . $request_ip . '|' . $blocked_ip->created;
		$unblock_url = remove_query_arg( 'unblock_ip', $this->self_uri() );
		
		// Handle unblock IP requests
		if( !empty( $_REQUEST['unblock_ip'] ) ) {
			if( $this->verify_nonce( $_REQUEST['unblock_ip'], $nonce_action ) )
				$this->unblock_ip( $request_ip );
			else
				$this->block_ip( 'medium' ); // Failed attempt to unblock IP, raise risk level and renew block
			
			wp_redirect( $unblock_url, 307 );
			die();
		}
		
		$message = 'Your IP address (' . $request_ip . ') has been blocked from accessing this website due to suspicous activity.';

		// Allow low risk IPs to unblock themselves
		if( 'low' == $blocked_ip->risk_level ) {
			// Obfuscate good unblock link with hidden links with identical text
			$good_link_num = mt_rand(2, 11);
			for( $i = 1; $i <= 12; $i++ ) {
				$link_nonce_action = $nonce_action;
				if( $good_link_num != $i )
					$link_nonce_action .= $i;
				$link_url = add_query_arg( 'unblock_ip', urlencode( $this->create_nonce( $link_nonce_action ) ), $unblock_url );
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
	private function get_request_ip() {
		$ip = $_SERVER['REMOTE_ADDR'];
		if( $this->block_internal_ips )
			$ip = (string) filter_var( $ip, FILTER_VALIDATE_IP );
		else
			$ip = (string) filter_var( $ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE );
		return $ip;
	}

	private function log_request() {
		$ip = $this->get_request_ip();
		if( empty( $ip ) )
			return;

		$now = current_time( 'mysql' );
		$query = $this->wpdb->prepare( "INSERT INTO $this->admin_access_log_table (ip, accessed) VALUES (INET6_ATON(%s), %s)", $ip, $now );
		$this->wpdb->query( $query );

		$query = $this->wpdb->prepare( "SELECT COUNT(1) as num_access_attempts FROM $this->admin_access_log_table WHERE ip=INET6_ATON(%s) AND 30 >= TIMESTAMPDIFF( MINUTE, accessed, %s )", $ip, $now );
		$num_access_attempts = $this->wpdb->get_var( $query );
		if( $num_access_attempts >= 5 )
			$this->block_ip();
	}

	private function block_ip( $risk_level = 'low' ) {
		$ip = $this->get_request_ip();
		if( empty( $ip ) )
			return;

		$now = current_time( 'mysql' );
		$query = $this->wpdb->prepare( "REPLACE INTO $this->blocked_table (ip, risk_level, created) VALUES (INET6_ATON(%s), %s, %s)", $ip, $risk_level, $now );
		$this->wpdb->query( $query );
	}

	private function unblock_ip( $ip ) {
		$query = $this->wpdb->prepare( "DELETE QUICK FROM $this->blocked_table WHERE ip=INET6_ATON(%s) LIMIT 1", $ip );
		$this->wpdb->query( $query );
	}

	private function is_blocked_ip() {
		$ip = $this->get_request_ip();
		if( empty( $ip ) )
			return false;

		$query = $this->wpdb->prepare( "SELECT * FROM $this->blocked_table WHERE ip=INET6_ATON(%s) LIMIT 1", $ip );
		$blocked = $this->wpdb->get_row( $query );
		return $blocked;
	}

	private function gc_table_data() {
		//Use HOUR units for better DB memcache support (redis)
		$blocked_timeout_in_hours = 1;

		$now = current_time('Y-m-d H:00:00');

		// Use DELETE QUICK for faster MyISAM (Aria) performance.
		// Skips the repacking of the table that normally occurs.
		// Since I/O on the admin access log and blocked tables are high, the file sizes don't really matter.

		// Delete expired ip blocks.
		$num_to_clean = $this->wpdb->get_var( "SELECT COUNT(1) as num_to_clean FROM $this->blocked_table WHERE $blocked_timeout_in_hours <= TIMESTAMPDIFF( HOUR, created, '$now' )" );
		if ( !empty( $num_to_clean ) ) {
			$num_to_clean = (int)( $num_to_clean / 4 ); // Only DELETE 25% at a time.
			if( $num_to_clean < 50 ) //Enforce minimum LIMIT for faster clean up
				$num_to_clean = 50;
			
			$this->wpdb->query( "DELETE QUICK FROM $this->blocked_table WHERE $blocked_timeout_in_hours <= TIMESTAMPDIFF( HOUR, created, '$now' ) LIMIT $num_to_clean" );
		}

		//Use DAY units for better DB memcache support (redis)
		$now = current_time('Y-m-d 00:00:00');

		// Delete old admin access log data
		$num_to_clean = $this->wpdb->get_var( "SELECT COUNT(1) as num_to_clean FROM $this->admin_access_log_table WHERE 2 <= TIMESTAMPDIFF( DAY, accessed, '$now' )" );
		if ( !empty( $num_to_clean ) ) {
			$num_to_clean = (int)( $num_to_clean / 4 ); // Only DELETE 25% at a time.
			if( $num_to_clean < 50 ) //Enforce minimum LIMIT for faster clean up
				$num_to_clean = 50;
			
			$this->wpdb->query( "DELETE QUICK FROM $this->admin_access_log_table WHERE 2 <= TIMESTAMPDIFF( HOUR, accessed, '$now' ) LIMIT $num_to_clean" );
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
