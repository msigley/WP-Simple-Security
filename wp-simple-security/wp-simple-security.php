<?php
/*
Plugin Name: WP Simple Security
Plugin URI: https://github.com/msigley
Description: Simple Security for preventing comment spam and brute force attacks.
Version: 2.2.0
Author: Matthew Sigley
License: GPL2
*/

class WPSimpleSecurity {
	private static $object = null;
	private $css_js_version = '1';
	private $login_token_name = null;
	private $login_token_value = null;
	private $login_use_tarpit = false;
	
	private function __construct () {
		//Login form protections
		if( !empty( constant('SIMPLE_SECURITY_LOGIN_TOKEN_NAME') ) && !empty( constant('SIMPLE_SECURITY_LOGIN_TOKEN_VALUE') ) ) {
			$this->login_token_name = SIMPLE_SECURITY_LOGIN_TOKEN_NAME;
			$this->login_token_value = SIMPLE_SECURITY_LOGIN_TOKEN_VALUE;
			$this->login_use_tarpit = !empty( constant('SIMPLE_SECURITY_LOGIN_USE_TARPIT') );

			//Prevent brute force attempts on wp-login.php
			$this->intercept_login_request();

			//Append login token to lostpassword_url
			add_filter('login_url', array($this, 'add_login_token_to_url'));
			add_filter('lostpassword_url', array($this, 'add_login_token_to_url'));

			//Force logout redirects to home page
			add_filter('logout_url', array($this, 'force_redirect_to_home'));
		
			//Add nonce checking to wp-login.php forms
			add_action('login_form', array($this, 'add_login_form_nonce'));
			add_action('register_form', array($this, 'add_login_form_nonce'));
			add_action('login_form_login', array($this, 'verify_login_form_nonce'));
			add_action('login_form_register', array($this, 'verify_login_form_nonce'));
		}

		//General protections
		if( !empty( constant('CSSJSVERSION') ) )
			$this->css_js_version = CSSJSVERSION;
		else
			$this->css_js_version = date('Ymd', current_time('timestamp'));

		//Removes the WordPress version from your header for security
		add_filter('the_generator', array($this, 'wb_remove_version'));
		//Removes detailed login error information for security
		add_filter('login_errors',create_function('$a', "return null;"));
		//Completely Disable Trackbacks
		add_filter('pings_open', array($this, 'disable_all_trackbacks'), 10, 2);
		//Removes Trackbacks from the comment count
		add_filter('get_comments_number', array($this, 'comment_count'), 0);
		//Limits the length of all fields from a comment form
		add_filter('preprocess_comment', array($this, 'limit_comment_field_length'));
		//Removes insecure information on dependancy includes
		add_action('wp_print_scripts', array($this, 'sanitize_scripts'), 9999);
		add_action('wp_print_styles', array($this, 'sanitize_styles'), 9999);
		//Replace Cheatin', uh? messages with something more professional
		//Uses the wordpress translation system
		add_filter('gettext', array($this, 'access_denied_message') );

		if( !is_admin() ) {
			//Remove Bad Comment Author URLS
			add_filter('get_comment_author_url', array($this, 'comment_author_url') );
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
			$comments_by_type = &separate_comments(get_comments('status=approve&post_id=' . $id));
			return count($comments_by_type['comment']);
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
			if ( defined('DOING_AJAX') )
				die( __('You are posting comments too quickly.  Slow down.') );
			wp_die( __('You are posting comments too quickly.  Slow down.') );
		}
		return $commentdata;
	}
	
	function access_denied_message( $translated_text ) {
		if( 'Cheatin&#8217; uh?' != $translated_text )
			return $translated_text;
		return 'Oops, so sorry! Action denied. If you feel you received this message by mistake, please contact us.';
	}


	/**
	 * Login token functions
	 */
	function intercept_login_request() {
		$script_name = strtolower( $_SERVER['PHP_SELF'] );

		if( !empty($_POST) || '/wp-login.php' !== $script_name )
			return;
		
		if( $_REQUEST['action'] == 'logout' || $_REQUEST['action'] == 'rp' ) {
			return;
		}

		if( empty( $_REQUEST[$this->login_token_name] ) || $_REQUEST[$this->login_token_name] !== $this->login_token_value ) {
			if( $this->login_use_tarpit )
				include 'includes/la_brea.php';
			wp_die( 'Access Denied', 'Access Denied', array( 'response' => 403 ) );
		}
	}

	function add_login_token_to_url( $url ) {
		if( is_admin() ) //Don't add security token to auth_redirects
			return $url;
		return add_query_arg($this->login_token_name, $this->login_token_value, $url);
	}

	function force_redirect_to_home($logout_url) {
		$logout_url = remove_query_arg('redirect_to', $logout_url);
		$logout_url = add_query_arg('redirect_to', urlencode(get_bloginfo('url')), $logout_url);
		return $logout_url;
	}

	/**
	 * Login nonce functions
	 */
	function add_login_form_nonce() {
		wp_nonce_field( 'simple_security_wp_login', 'simple_security_wp_login' );
	}

	function verify_login_form_nonce() {
		if( empty($_POST) )
			return;
		
		if( $this->login_use_tarpit ) {
			if( wp_verify_nonce( $_REQUEST['simple_security_wp_login'], 'simple_security_wp_login' ) )
				return;
			else
				include 'includes/la_brea.php';
		}

		check_admin_referer( 'simple_security_wp_login', 'simple_security_wp_login' );
	}
}
$WPSimpleSecurity = WPSimpleSecurity::object();