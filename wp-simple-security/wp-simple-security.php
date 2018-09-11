<?php
/*
Plugin Name: WP Simple Security
Plugin URI: https://github.com/msigley
Description: Simple Security for preventing comment spam and brute force attacks.
Version: 2.6.1
Author: Matthew Sigley
License: GPL2
*/

class WPSimpleSecurity {
	private static $object = null;
	private $css_js_version = '1';
	private $use_tarpit = false;
	private $login_token_name = null;
	private $login_token_value = null;
	private $site_root = '';
	private $script_name = '';
	
	private function __construct() {
		$this->site_root = strtolower( site_url() );
		$this->site_root = substr( $this->site_root, strpos( $this->site_root, $_SERVER['SERVER_NAME'] ) + strlen( $_SERVER['SERVER_NAME'] ) );
		$this->script_name = strtolower( $_SERVER['SCRIPT_NAME'] );

		if( defined( 'SIMPLE_SECURITY_USE_TARPIT' ) )
			$this->use_tarpit = !empty( SIMPLE_SECURITY_USE_TARPIT );
		
		//Completely Disable XMLRPC API
		$this->intercept_xmlrpc_request();

		//Login form protections
		if( defined( 'SIMPLE_SECURITY_LOGIN_TOKEN_NAME' ) && defined( 'SIMPLE_SECURITY_LOGIN_TOKEN_VALUE' ) 
			&& !empty( SIMPLE_SECURITY_LOGIN_TOKEN_NAME ) && !empty( SIMPLE_SECURITY_LOGIN_TOKEN_VALUE ) ) {
			$this->login_token_name = SIMPLE_SECURITY_LOGIN_TOKEN_NAME;
			$this->login_token_value = SIMPLE_SECURITY_LOGIN_TOKEN_VALUE;

			//Append login token to lostpassword_url
			add_filter( 'login_url', array( $this, 'add_login_token_to_url' ) );
			add_filter( 'lostpassword_url', array( $this, 'add_login_token_to_url' ) );

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
			} else {
				//Prevent brute force attempts on wp-login.php
				$this->intercept_login_request();
			}
		}

		//General protections
		if( defined('CSSJSVERSION') && !empty( CSSJSVERSION ) )
			$this->css_js_version = CSSJSVERSION;
		else
			$this->css_js_version = date( 'Ymd', current_time( 'timestamp' ) );

		//Removes the WordPress version from your header for security
		add_filter( 'the_generator', array( $this, 'wb_remove_version' ) );
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
			//Uses the wordpress translation system
			add_filter( 'gettext', array( $this, 'access_denied_message' ) );
			
			//Remove author query vars to prevent DB enumeration
			add_filter('query_vars', array( $this, 'remove_insecure_query_vars' ) );
			//Remove Bad Comment Author URLS
			add_filter( 'get_comment_author_url', array( $this, 'comment_author_url' ) );
		}
	}
	
	static function &object() {
		if ( ! self::$object instanceof WPSimpleSecurity ) {
			self::$object = new WPSimpleSecurity();
		}
		return self::$object;
	}
	
	/**
	 * General protection functions
	 */
	public function sanitize_scripts() {
		global $wp_scripts;
		
		foreach( $wp_scripts->queue as $enqueued_script ) {
			$wp_scripts->registered[$enqueued_script]->ver = $this->css_js_version;
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
	
	function access_denied_message( $translated_text ) {
		if( 'Cheatin&#8217; uh?' != $translated_text )
			return $translated_text;
		return 'Oops, so sorry! Action denied. If you feel you received this message by mistake, please contact us.';
	}

	public function remove_insecure_query_vars( $allowed_query_vars ) {
		return array_diff( $allowed_query_vars, array( 'author' ) );
	}

	public function sanitize_thumbnail_paths( $thumbnail_data ) {
		if( isset( $thumbnail_data['thumb'] ) )
			$thumbnail_data['thumb'] = basename( $thumbnail_data['thumb'] );
	}

	/**
	 * WP API protection functions
	 */
	function intercept_xmlrpc_request() {
		$script_name = strtolower( $_SERVER['SCRIPT_NAME'] );

		if( $this->site_root . '/xmlrpc.php' === $this->script_name ) {
			if( $this->use_tarpit )
				include 'includes/la_brea.php';
			
			add_filter( 'wp_die_xmlrpc_handler', function( $die_handler ) { return '_default_wp_die_handler'; } );
			wp_die( 'Access Denied', 'Access Denied', array( 'response' => 403 ) );
		}
	}

	/**
	 * Login protection functions
	 */
	function intercept_login_request() {
		if( 'POST' == $_SERVER['REQUEST_METHOD'] || $this->site_root . '/wp-login.php' !== $this->script_name )
			return;
		
		if( $_REQUEST['action'] == 'logout' || $_REQUEST['action'] == 'rp' ) {
			return;
		}

		if( empty( $_REQUEST[$this->login_token_name] ) || $_REQUEST[$this->login_token_name] !== $this->login_token_value ) {
			if( $this->use_tarpit )
				include 'includes/la_brea.php';
			wp_die( 'Access Denied', 'Access Denied', array( 'response' => 403 ) );
		}
	}

	function add_login_token_to_url( $url ) {
		if( is_admin() ) //Don't add security token to auth_redirects
			return $url;
		return add_query_arg( $this->login_token_name, $this->login_token_value, $url );
	}

	function force_redirect_to_home( $logout_url ) {
		$logout_url = remove_query_arg( 'redirect_to', $logout_url );
		$logout_url = add_query_arg( 'redirect_to', urlencode( get_bloginfo( 'url' ) ), $logout_url );
		return $logout_url;
	}

	function hide_login_errors( $null=null, $username='', $password='' ) {
		if( remove_query_arg( 'redirect_to', $_SERVER['HTTP_REFERER'] ) !== wp_login_url() )
			return; //Do nothing for plugin login handlers
		
		if( empty( $username ) || empty( $password ) ) {
			$login_url = wp_login_url();
			if( !empty( $_REQUEST['redirect_to'] ) )
				$login_url = add_query_arg( 'redirect_to', urlencode( $login_url ), $login_url );
			wp_redirect( wp_login_url() );
		}
	}

	function add_login_form_nonce() {
		$this->nonce_field( 'simple_security_wp_login', 'simple_security_wp_login' );
	}

	function verify_login_form_post() {
		if( remove_query_arg( 'redirect_to', $_SERVER['HTTP_REFERER'] ) === wp_login_url() 
			&& $this->verify_nonce( $_REQUEST['simple_security_wp_login'], 'simple_security_wp_login' ) )
			return;

		if( $this->use_tarpit )
			include 'includes/la_brea.php';

		wp_die( 'Access Denied', 'Access Denied', array( 'response' => 403 ) );
	}

	/**
	 * Nonce functions
	 */
	function nonce_field( $action = -1, $name = "_nonce", $echo = true ) {
		$name = esc_attr( $name );
		$nonce_field = '<input type="hidden" id="' . $name . '" name="' . $name . '" value="' . $this->create_nonce( $action ) . '" />';

		if ( $echo )
			echo $nonce_field;

		return $nonce_field;
	}

	function verify_nonce( $nonce, $action = -1 ) {
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

	function create_nonce( $action = -1 ) {
		$i = wp_nonce_tick();

		return substr(wp_hash($i . '|' . $action, 'nonce'), -12, 10);
	}
}
$WPSimpleSecurity = WPSimpleSecurity::object();
