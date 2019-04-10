<?php
/*
Plugin Name: Login rebuilder
Plugin URI: https://elearn.jp/wpman/column/login-rebuilder.html
Description: This plug-in will make a new login page for your site.
Author: tmatsuur
Version: 2.5.1
Author URI: https://12net.jp/
Text Domain: login-rebuilder
Domain Path: /languages
*/

/*
 Copyright (C) 2013-2018 tmatsuur (Email: takenori dot matsuura at 12net dot jp)
This program is licensed under the GNU GPL Version 2.
*/

define( 'LOGIN_REBUILDER_DOMAIN', 'login-rebuilder' );
define( 'LOGIN_REBUILDER_DB_VERSION_NAME', 'login-rebuilder-db-version' );
define( 'LOGIN_REBUILDER_DB_VERSION', '2.5.1' );
define( 'LOGIN_REBUILDER_PROPERTIES', 'login-rebuilder' );
define( 'LOGIN_REBUILDER_LOGGING_NAME', 'login-rebuilder-logging' );

$plugin_login_rebuilder = new login_rebuilder();

class login_rebuilder {
	const LOGIN_REBUILDER_PROPERTIES_NAME			= 'login-rebuilder-properties';

	const LOGIN_REBUILDER_RESPONSE_403				= 1;
	const LOGIN_REBUILDER_RESPONSE_404				= 2;
	const LOGIN_REBUILDER_RESPONSE_GO_HOME			= 3;

	const LOGIN_REBUILDER_STATUS_IN_PREPARATION		= 0;
	const LOGIN_REBUILDER_STATUS_WORKING			= 1;

	const LOGIN_REBUILDER_LOGGING_OFF				= 0;
	const LOGIN_REBUILDER_LOGGING_INVALID_REQUEST	= 1;
	const LOGIN_REBUILDER_LOGGING_LOGIN				= 2;
	const LOGIN_REBUILDER_LOGGING_ALL				= 3;

	const LOGIN_REBUILDER_LOGGING_LIMIT				= 200;
	const LOGIN_REBUILDER_LOGGING_LIMIT_MIN			= 100;
	const LOGIN_REBUILDER_LOGGING_LIMIT_MAX			= 1000;

	const LOGIN_REBUILDER_ACCESS_AUTHOR_PAGE_ACCEPT	= 0;
	const LOGIN_REBUILDER_ACCESS_AUTHOR_PAGE_404	= 1;

	const LOGIN_REBUILDER_OEMBED_DEFAULT			= 0;
	const LOGIN_REBUILDER_OEMBED_HIDE_AUTHOR		= 1;
	const LOGIN_REBUILDER_OEMBED_DONT_OUTPUT		= 2;

	const LOGIN_REBUILDER_NONCE_NAME				= 'login-rebuilder-nonce';
	const LOGIN_REBUILDER_NONCE_LIFETIME			= 1800;
	const LOGIN_REBUILDER_AJAX_NONCE_NAME			= 'login-rebuilder-ajax-nonce';

	const XMLRPC_PROPERTIES_NAME					= 'login-rebuilder-xmlrpc-properties';
	const XMLRPC_NONCE_NAME							= 'xmlrpc-nonce';

	const PINGBACK_RECEIVE_STATUS_REFUSE			= 0;
	const PINGBACK_RECEIVE_STATUS_ACCEPT			= 1;

	const XMLRPC_ENHANCED_IN_PREPARATION			= 0;
	const XMLRPC_ENHANCED_WORKING					= 1;

	const INVALID_REMOTE_ADDR = '0.0.0.0';
	const LOG_BOX_STYLES = 'max-height: 13.5em; overflow: auto; font-family: monospace; color: #777; background-color: #FFFFFF; border: 1px solid #DDDDDD; padding: .25em;';

	const PRIORITY_ROLE_AUTHENTICATE				= 9199;
	const PRIORITY_AMBIGUOUS_ERROR_MESSAGE			= 9999;

	private $candidate = array( 'new-login.php', 'your-login.php', 'admin-login.php', 'wordpress-login.php', 'hidden-login.php' );
	private $properties;
	private $content = "<?php
define( 'LOGIN_REBUILDER_SIGNATURE', '%sig%' );
require_once './wp-login.php';
?>";
	private $root_url;		// trailing slash is removed
	private $root_path;		// trailing slash is removed
	private $use_site_option = true;
	private $logging_widget;

	private $remote_addr;	// maybe $_SERVER['REMOTE_ADDR']
	private $request_uri;	// maybe $_SERVER['REQUEST_URI']

	/**
	 * Construction.
	 *
	 * @since 1.0.0
	 *
	 * @global $_SERVER.
	 */
	public function __construct() {
		register_activation_hook( __FILE__ , array( &$this , 'activation' ) );
		register_deactivation_hook( __FILE__ , array( &$this , 'deactivation' ) );

		if ( ! empty( $_SERVER['HTTP_CLIENT_IP'] ) ) {
			$remote_addr = $_SERVER['HTTP_CLIENT_IP'];
		} else if ( ! empty( $_SERVER['HTTP_X_FORWARDED_FOR'] ) ) {
			$ip_array = explode( ',', $_SERVER['HTTP_X_FORWARDED_FOR'] );
			$remote_addr = $ip_array[0];
		} else {
			$remote_addr = $_SERVER['REMOTE_ADDR'];
		}
		$this->remote_addr = preg_match( '/^(([1-9]?[0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]).){3,5}([1-9]?[0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$/', $remote_addr )? $remote_addr: self::INVALID_REMOTE_ADDR;
		$this->request_uri = $this->_sanitize_url( $_SERVER['REQUEST_URI'] );

		$this->root_url = ( ( is_ssl() || force_ssl_admin() )? "https://": "http://" ).$_SERVER['SERVER_NAME'];
		$this->root_path = $_SERVER['DOCUMENT_ROOT'];
		if ( empty( $this->root_path ) ) {
			list( $scheme, $content_uri ) = explode( "://".$_SERVER['SERVER_NAME'], get_option( 'siteurl' ) );
			$this->root_path = preg_replace( '/'.str_replace( array( '-', '.', '/' ), array( '\\-', '\\.', '[\\/\\\\]' ), $content_uri ).'/u', '', untrailingslashit( ABSPATH ) );
		}

		if ( is_multisite() && ! is_main_site( get_current_blog_id() ) ) {
			// [2.4.4] bugfix: installed in subdirectory
			$this->use_site_option = false;
		}
		$this->_load_option();
		if ( $this->properties['status'] == self::LOGIN_REBUILDER_STATUS_WORKING &&
			( !@file_exists( $this->_login_file_path( $this->properties['page'] ) ) || !$this->_is_valid_new_login_file() ) ) {
			$this->properties['status'] = self::LOGIN_REBUILDER_STATUS_IN_PREPARATION;
		}

		add_action( 'admin_menu', array( &$this, 'admin_menu' ) );
		add_action( 'admin_init', array( &$this, 'admin_init' ) );
		add_action( 'wp_ajax_login_rebuilder_try_save', array( &$this, 'try_save' ) );
		add_action( 'wp_ajax_login_rebuilder_lock_exists', array( &$this, 'lock_exists' ) );
		add_action( 'wp_ajax_login_rebuilder_download_log', array( &$this, 'download_log' ) );

		add_filter( 'plugin_row_meta', array( &$this, 'plugin_row_meta' ), 9, 4 );	// [2.0.0] Changed to 4 from 2 the number of parameters.
		add_filter( 'site_url', array( &$this, 'site_url' ), 10, 4 );
		add_filter( 'network_site_url', array( &$this, 'network_site_url' ), 10, 3 );
		add_filter( 'wp_redirect', array( &$this, 'wp_redirect' ), 10, 2 );

		if ( $this->properties['status'] == self::LOGIN_REBUILDER_STATUS_WORKING ) {
			add_action( 'login_init', array( &$this, 'login_init' ) );
			add_filter( 'login_redirect', array( &$this, 'login_redirect' ), 10, 3 );
			if ( $this->properties['logging'] == self::LOGIN_REBUILDER_LOGGING_ALL ||
				$this->properties['logging'] == self::LOGIN_REBUILDER_LOGGING_LOGIN ) {
				add_action( 'wp_login_failed', array( &$this, 'wp_login_failed' ), 10, 1 );
			}
			add_filter( 'authenticate', array( &$this, 'role_authenticate' ), self::PRIORITY_ROLE_AUTHENTICATE, 3 );
			if ( isset( $this->properties['ambiguous_error_message'] ) && $this->properties['ambiguous_error_message'] ) {	// [2.1.0]
				add_filter( 'authenticate', array( &$this, 'ambiguous_error_message' ), self::PRIORITY_AMBIGUOUS_ERROR_MESSAGE, 3 );
			}
			if ( isset( $this->properties['disable_authenticate_email_password'] ) && $this->properties['disable_authenticate_email_password'] &&
				function_exists( 'wp_authenticate_email_password' ) )	{ // [2.1.0]
				remove_filter( 'authenticate', 'wp_authenticate_email_password', 20 );
			}
			if ( isset( $this->properties['access_author_page'] ) &&
				$this->properties['access_author_page'] == self::LOGIN_REBUILDER_ACCESS_AUTHOR_PAGE_404 ) {	// [2.4.0]
				add_filter( 'redirect_canonical', array( &$this, 'author_page_canonical' ), 10, 2 );
				add_action( 'template_redirect', array( &$this, 'author_page_404' ) );
			}
			if ( isset( $this->properties['oembed'] ) &&
				$this->properties['oembed'] != self::LOGIN_REBUILDER_OEMBED_DEFAULT ) {	// [2.4.1]
				add_filter( 'oembed_response_data',	array( &$this, 'oembed_hide_author_data' ), 10, 4 );	// hide author name and url
				if ( $this->properties['oembed'] == self::LOGIN_REBUILDER_OEMBED_DONT_OUTPUT ) {
					remove_action( 'wp_head', 'wp_oembed_add_discovery_links' );							// Don't output links
					add_filter( 'rest_pre_dispatch', array( &$this, 'disable_oembed_request' ), 10, 3 );	// disable oembed request
				}
			}
			add_filter( 'user_request_action_email_content', array( &$this, 'set_original_confirmaction_url' ), 10, 2 );	// [2.4.2]

			if ( isset( $this->properties['locked_status_popup'] ) && $this->properties['locked_status_popup'] ) {	// [2.5.0]
				add_filter( 'login_errors', array( &$this, 'login_locked_status' ), 10, 1 );
				add_filter( 'login_messages', array( &$this, 'login_locked_status' ), 10, 1 );
			}
			add_filter( 'determine_locale', array( &$this, 'determined_locale' ), 10, 1 );	// [2.5.0]
		}
		if ( $this->_is_wp_version( '3.5', '>=' ) ) {
			$this->_xmlrpc_actions();
		}
	}
	/**
	 * Plugin activation.
	 *
	 * @since 1.0.0
	 * @since 1.3.0 Changed to 'activation' from 'init' the name of this method.
	 *
	 * @access public.
	 *
	 * @see self::__construct().
	 */
	public function activation() {
		if ( get_option( LOGIN_REBUILDER_DB_VERSION_NAME ) != LOGIN_REBUILDER_DB_VERSION ) {
			update_option( LOGIN_REBUILDER_DB_VERSION_NAME, LOGIN_REBUILDER_DB_VERSION );
		}
	}
	/**
	 * Plugin deactivation.
	 *
	 * @since 1.0.0
	 *
	 * @access public.
	 *
	 * @see self::__construct().
	 */
	public function deactivation() {
		$this->_delete_private_nonce();
		delete_option( LOGIN_REBUILDER_DB_VERSION_NAME );
		$this->_delete_logging();

		$this->properties['status'] = self::LOGIN_REBUILDER_STATUS_IN_PREPARATION;
		$this->_save_option();
	}
	/**
	 * Cope with when accessed to the invalid login page.
	 *
	 * @since 1.0.0
	 * @since 2.0.0 Added the flag of the XML-RPC request to the log data.
	 *
	 * @access public.
	 *
	 * @see self::__construct().
	 *
	 * @global $_GET, $_POST.
	 */
	public function login_init() {
		if ( $this->_is_wp_version( '4.9.6', '>=' ) && isset( $_GET['action'] ) && $_GET['action'] == 'confirmaction' ) return;		// [2.4.2] User request confirm
		if ( isset( $_GET['action'] ) && $_GET['action'] == 'postpass' ) return;				// Password reset
		if ( get_option( 'users_can_register' ) && !$this->properties['reject_user_register'] &&
			( ( isset( $_GET['action'] ) && $_GET['action'] == 'register' ) ||
			( isset( $_GET['checkemail'] ) && $_GET['checkemail'] == 'registered' ) ) ) return;	// [2.2.0] User registration

		load_plugin_textdomain( LOGIN_REBUILDER_DOMAIN, false, plugin_basename( dirname( __FILE__ ) ).'/languages' );
		if ( preg_match( '/\/wp\-login\.php/u', $this->request_uri ) ||
			!( ( $this->_in_url( $this->request_uri, $this->properties['page'] ) || $this->_in_url( $this->request_uri, $this->properties['page_subscriber'] ) ) && defined( 'LOGIN_REBUILDER_SIGNATURE' ) && $this->properties['keyword'] == LOGIN_REBUILDER_SIGNATURE ) ) {
			if ( $this->properties['logging'] == self::LOGIN_REBUILDER_LOGGING_ALL ||
				 $this->properties['logging'] == self::LOGIN_REBUILDER_LOGGING_INVALID_REQUEST ) {
				$this->_logging(
					'invalid',
					array(
						'time'=>time(),
						'ip'=>$this->remote_addr,
						'uri'=>$this->request_uri,
						'id'=>( empty( $_POST['log'] )? '': $_POST['log'] ),
						'pw'=>( empty( $_POST['pwd'] )? '': $_POST['pwd'] ),
						'xmlrpc'=>false	// Since 2.0.0
				 		)
					);
			}
			switch ( $this->properties['response'] ) {
				case self::LOGIN_REBUILDER_RESPONSE_GO_HOME:
					wp_redirect( home_url() );
					break;
				case self::LOGIN_REBUILDER_RESPONSE_404:
					status_header( 404 );
					break;
				case self::LOGIN_REBUILDER_RESPONSE_403:
				default:
					status_header( 403 );
					break;
			}
			exit;
		}
	}
	/**
	 * Save a log of login success.
	 *
	 * @since 1.2.0
	 * @since 2.2.0 Send notify mail.
	 *
	 * @access public.
	 *
	 * @see self::__construct().
	 */
	public function login_redirect( $redirect_to, $requested_redirect_to, $user ) {
		if ( !is_wp_error( $user ) ) {
			if ( $this->properties['logging'] == self::LOGIN_REBUILDER_LOGGING_ALL ||
				$this->properties['logging'] == self::LOGIN_REBUILDER_LOGGING_LOGIN ) {
				$this->_logging(
					'login',
					array(
						'time'=>time(),
						'ip'=>$this->remote_addr,
						'uri'=>$this->request_uri,
						'id'=>$user->ID )
					);
			}
			if ( $this->properties['notify_admin_login'] && user_can( $user, 'manage_options' ) ) {
				$this->_notify_admin_login( $user );
			}
		}
		return $redirect_to;
	}

	/**
	 * Save a log of login failures.
	 *
	 * @since 1.4.0
	 * @since 2.0.0 Added the flag of the XML-RPC request to the log data.
	 *
	 * @access public.
	 *
	 * @see self::__construct(), self::login_init().
	 *
	 * @global $_POST, XMLRPC_REQUEST.
	 */
	public function wp_login_failed( $username ) {
		$this->_logging(
			'invalid',
			array(
				'time'=>time(),
				'ip'=>$this->remote_addr,
				'uri'=>$this->request_uri,
				'id'=>$username,
				'pw'=>( empty( $_POST['pwd'] )? '': $_POST['pwd'] ),
				'xmlrpc'=>( defined( 'XMLRPC_REQUEST') && XMLRPC_REQUEST )	// Since 2.0.0
				)
			);
	}

	/**
	 * Display some of the widgets in the dashboard.
	 *
	 * @since 1.4.4
	 * @since 2.0.0 Added log of pingback widget.
	 *
	 * @access public.
	 *
	 * @see self::__construct().
	 */
	public function admin_init() {
		global $pagenow;
		if ( current_user_can( 'manage_options' ) && in_array( $pagenow, array( 'index.php' ) ) ) {
			$this->logging_widget = $this->_get_logging();
			if ( isset( $this->logging_widget['invalid'] ) && is_array( $this->logging_widget['invalid'] ) && count( $this->logging_widget['invalid'] ) > 0 ) {
				krsort( $this->logging_widget['invalid'] );
				add_meta_box( 'meta_box_dashboard_log_of_invalid_request', __( 'Log of invalid request', LOGIN_REBUILDER_DOMAIN ),
						array( &$this, 'meta_box_log_of_invalid_request' ), 'dashboard', 'side', 'high' );
			}
			if ( isset( $this->logging_widget['login'] ) && is_array( $this->logging_widget['login'] ) && count( $this->logging_widget['login'] ) > 0 ) {
				krsort( $this->logging_widget['login'] );
				add_meta_box( 'meta_box_dashboard_log_of_login', __( 'Log of login', LOGIN_REBUILDER_DOMAIN ),
					array( &$this, 'meta_box_log_of_login' ), 'dashboard', 'side', 'high' );
			}
			// [2.0.0]
			if ( isset( $this->logging_widget['pingback'] ) && is_array( $this->logging_widget['pingback'] ) && count( $this->logging_widget['pingback'] ) > 0 ) {
				krsort( $this->logging_widget['pingback'] );
				add_meta_box( 'meta_box_dashboard_log_of_pingback', __( 'Log of pingback', LOGIN_REBUILDER_DOMAIN ),
					array( &$this, 'meta_box_log_of_pingback' ), 'dashboard', 'side', 'high' );
			}
		}
	}

	/**
	 * Log of invalid request(access to the wp-login.php) callback.
	 *
	 * @since 1.4.4
	 *
	 * @access public.
	 *
	 * @see self::admin_init()
	 */
	public function meta_box_log_of_invalid_request() {
		$this->_view_log_of_invalid_request( $this->logging_widget['invalid'] );
	}

	/**
	 * Log of login widget callback.
	 *
	 * @since 1.4.4
	 *
	 * @access public.
	 *
	 * @see self::admin_init()
	 */
	public function meta_box_log_of_login() {
		$this->_view_log_of_login( $this->logging_widget['login'] );
	}

	/**
	 * Log of pingback widget callback.
	 *
	 * @since 2.0.0
	 *
	 * @access public.
	 *
	 * @see self::admin_init()
	 */
	public function meta_box_log_of_pingback() {
		$this->_view_log_of_pingback( $this->logging_widget['pingback'] );
	}

	/**
	 * URL is adjusted to the case of the login page on single site('site_url' filter).
	 *
	 * @since 1.0.0
	 *
	 * @access public.
	 *
	 * @see self::__construct(), get_site_url().
	 *
	 * @global $_SREVER.
	 *
	 * @param string      $url     The complete site URL including scheme and path.
	 * @param string      $path    Path relative to the site URL. Blank string if no path is specified.
	 * @param string|null $scheme  Scheme to give the site URL context. Accepts 'http', 'https', 'login',
	 *                             'login_post', 'admin', 'relative' or null.
	 * @param int|null    $blog_id Blog ID, or null for the current blog.
	 * @return string     Site url link.
	 */
	public function site_url( $url, $path, $orig_scheme, $blog_id ) {
		if ( $this->properties['status'] == self::LOGIN_REBUILDER_STATUS_WORKING ) {
			$my_login_page = $this->properties['page'];
			if ( function_exists( 'wp_get_current_user' ) )
				$user = wp_get_current_user();
			else
				$user = (object)array( 'data'=>null );
			if ( $this->properties['page_subscriber'] != '' && ( $this->_in_url( $this->request_uri, $this->properties['page_subscriber'] ) || ( isset( $user->data ) && $this->_is_secondary_login_user( $user ) ) ) )
				$my_login_page = $this->properties['page_subscriber'];

			if ( ( $path == 'wp-login.php' || preg_match( '/wp-login\.php\?action=\w+/', $path ) ) &&
				( is_user_logged_in() || $this->_in_url( $this->request_uri, $my_login_page ) ) )
				$url = $this->_rewrite_login_url( 'wp-login.php', $my_login_page, $url );
		}
		return $url;
	}

	/**
	 * URL is adjusted to the case of the login page on multi site('network_site_url' filter).
	 *
	 * @since 1.3.1
	 *
	 * @access public.
	 *
	 * @see self::__construct(), network_site_url().
	 *
	 * @param string      $url    The complete network site URL including scheme and path.
	 * @param string      $path   Path relative to the network site URL. Blank string if
	 *                            no path is specified.
	 * @param string|null $scheme Scheme to give the URL context. Accepts 'http', 'https',
	 *                            'relative' or null.
	 * @return string     Site url link.
	 */
	public function network_site_url( $url, $path, $scheme ) {
		return $this->site_url( $url, $path, $scheme, 0 );
	}

	/**
	 * URL is adjusted to the case of the login page('wp_redirect' filter).
	 *
	 * @since 1.0.0
	 *
	 * @access public.
	 *
	 * @see self::__construct(), wp_redirect().
	 *
	 * @param string  $location The path to redirect to.
	 * @param int     $status   Status code to use.
	 * @return string The path to redirect to.
	 */
	public function wp_redirect( $location, $status ) {
		if ( $this->properties['status'] == self::LOGIN_REBUILDER_STATUS_WORKING ) {
			$my_login_page = $this->properties['page'];
			if ( function_exists( 'wp_get_current_user' ) )
				$user = wp_get_current_user();
			else
				$user = (object)array( 'data'=>null );
			if ( $this->properties['page_subscriber'] != '' && ( $this->_in_url( $this->request_uri, $this->properties['page_subscriber'] ) || ( isset( $user->data ) && $this->_is_secondary_login_user( $user ) ) ) )
				$my_login_page = $this->properties['page_subscriber'];

			if ( $this->_in_url( $this->request_uri, $my_login_page ) )
				$location = $this->_rewrite_login_url( 'wp-login.php', $my_login_page, $location );
			else if ( preg_match( '/reauth\=1$/u', $location ) ) {
				if ( is_user_admin() )
					$scheme = 'logged_in';
				else
					$scheme = apply_filters( 'auth_redirect_scheme', '' );
				if ( $cookie_elements = wp_parse_auth_cookie( '',  $scheme ) ) {
					extract( $cookie_elements, EXTR_OVERWRITE );
					$user = get_user_by( 'login', $username );
					if ( $user ) // timeout
						$location = $this->_rewrite_login_url( 'wp-login.php?', $my_login_page.'?', $location );
				}
			}
		}
		return $location;
	}

	/**
	 * Returns the URL that allows the users other than the administrator to log in to the site.
	 *
	 * @since 1.4.3
	 *
	 * @access public.
	 *
	 * @param string $redirect Path to redirect to on login. Optional. Default: ''.
	 * @param int    $blog_id The id of the blog. Optional. Default: 0 (current blog).
	 * @return string Secondary log in URL.
	 */
	public function wp_secondary_login_url( $redirect = '', $blog_id = 0 ) {
		$login_url = '';
		if ( is_multisite() && !empty( $blog_id ) ) {
			switch_to_blog( $blog_id );
			$site_url = get_option( 'siteurl' );
			$blog_properties = get_option( LOGIN_REBUILDER_PROPERTIES );
			restore_current_blog();
			if ( isset( $blog_properties['status'] ) && $blog_properties['status'] == self::LOGIN_REBUILDER_STATUS_WORKING && !empty( $blog_properties['page_subscriber'] ) ) {
				$login_url = set_url_scheme( $site_url, 'login' );
				$login_url .= '/' . ltrim( $blog_properties['page_subscriber'], '/' );
				if ( !empty( $redirect ) )
					$login_url = add_query_arg( 'redirect_to', urlencode( $redirect ), $login_url );
			}
		} else {
			if ( $this->properties['status'] == self::LOGIN_REBUILDER_STATUS_WORKING && !empty( $this->properties['page_subscriber'] ) ) {
				$login_url = $this->_login_file_url( $this->properties['page_subscriber'] );
				if ( !empty( $redirect ) )
					$login_url = add_query_arg( 'redirect_to', urlencode( $redirect ), $login_url );
			}
		}
		return $login_url;
	}

	/**
	 * By login page to limit the user's role('authenticate' filter).
	 *
	 * @since 1.1.0
	 * @since 1.4.0 Changed to 'role_authenticate' from 'subscriber_authenticate' the name of this method.
	 * @since 2.5.0 Login fails whenever a lock file exists.
	 *
	 * @access public.
	 *
	 * @see self::__construct(), wp_authenticate().
	 *
	 * @param null|WP_User $user     User to authenticate.
	 * @param string       $username User login.
	 * @param string       $password User password
	 * @return null|WP_User|WP_Error User to authenticate.
	 */
	public function role_authenticate( $user, $username, $password ) {
		if ( ! is_a( $user, 'WP_User' ) ) {
			return $user;
		}

		// [2.5.0] login lock file exists
		if ( $this->_in_url( $this->request_uri, $this->properties['page'] ) &&
			$this->_lock_file_valid( $this->properties['use_lock_file'], $this->properties['lock_file_path'] ) ) {
			return $this->_invalid_username_or_incorrect_password();
		}

		if ( $this->properties['page_subscriber'] != '' &&
			$this->_is_valid_new_login_file( $this->properties['page_subscriber'] ) ) {
			// secondary login file exists
			if ( $this->_in_url( $this->request_uri, $this->properties['page_subscriber'] ) ) {
				// secondary login file
				if ( !$this->_is_secondary_login_user( $user ) ) {
					return $this->_invalid_username_or_incorrect_password();
				}
			} else {
				// new login file
				if ( !$this->_is_not_secondary_login_user( $user ) ) {
					return $this->_invalid_username_or_incorrect_password();
				}
			}
		}
		return $user;
	}

	/**
	 * To cancel the `role_authenticate` filter.
	 *
	 * @since 2.1.1
	 *
	 * @access public.
	 *
	 * @see self::role_authenticate().
	 */
	public function cancel_role_authenticate() {
		remove_filter( 'authenticate', array( &$this, 'role_authenticate' ), self::PRIORITY_ROLE_AUTHENTICATE );
	}

	/**
	 * To change to the ambiguous message in some cases.
	 *
	 * @since 2.1.0
	 *
	 * @access public.
	 *
	 * @see self::__construct(), wp_authenticate().
	 *
	 * @param null|WP_User $user     User to authenticate.
	 * @param string       $username User login.
	 * @param string       $password User password
	 * @return null|WP_User|WP_Error User to authenticate.
	 */
	public function ambiguous_error_message( $user, $username, $password ) {
		$ambiguous_codes = array( 'invalid_username', 'invalid_email', 'incorrect_password' );
		if ( is_wp_error( $user ) && in_array( $user->get_error_code(), $ambiguous_codes ) ) {
			return $this->_invalid_username_or_incorrect_password();
		}
		return $user;
	}

	/**
	 * Added this plugin properties menu('plugin_row_meta' filter).
	 *
	 * @since 1.0.0
	 * @since 2.0.0 Conforming parameters to the specification.
	 *
	 * @access public.
	 *
	 * @see self::__construct().
	 *
	 * @param array  $plugin_meta An array of the plugin's metadata,
	 *                            including the version, author,
	 *                            author URI, and plugin URI.
	 * @param string $plugin_file Path to the plugin file, relative to the plugins directory.
	 * @param array  $plugin_data An array of plugin data.
	 * @param string $status      Status of the plugin. Defaults are 'All', 'Active',
	 *                            'Inactive', 'Recently Activated', 'Upgrade', 'Must-Use',
	 *                            'Drop-ins', 'Search'.
	 * @return array.
	 */
	public function plugin_row_meta( $plugin_meta, $plugin_file, $plugin_data, $status ) {
		if ( $plugin_file == plugin_basename( dirname( __FILE__ ) ).'/'.basename( __FILE__ ) ) {
			$plugin_meta[] = '<a href="options-general.php?page='.self::LOGIN_REBUILDER_PROPERTIES_NAME.'">'.__( 'Settings' ).'</a>';
		}
		return $plugin_meta;
	}

	/**
	 * Added this plugin menu('admin_menu' action).
	 *
	 * @since 1.0.0
	 *
	 * @access public.
	 *
	 * @see self::__construct().
	 */
	public function admin_menu() {
		load_plugin_textdomain( LOGIN_REBUILDER_DOMAIN, false, plugin_basename( dirname( __FILE__ ) ).'/languages' );
		add_options_page( _x( 'Login rebuilder', 'menu', LOGIN_REBUILDER_DOMAIN ), _x( 'Login rebuilder', 'menu', LOGIN_REBUILDER_DOMAIN ), 'manage_options', self::LOGIN_REBUILDER_PROPERTIES_NAME, array( &$this, 'properties' ) );

		if ( $this->_is_wp_version( '3.5', '>=' ) ) {	// [2.0.0]
			add_options_page( __( 'XML-RPC', LOGIN_REBUILDER_DOMAIN ), __( 'XML-RPC', LOGIN_REBUILDER_DOMAIN ), 'manage_options', self::XMLRPC_PROPERTIES_NAME, array( &$this, 'xmlrpc_properties' ) );
		}
	}

	/**
	 * This plugin properties page content.
	 *
	 * @since 1.0.0
	 * @since 2.0.0 Splitting the HTML output section.
	 *
	 * @access public.
	 *
	 * @see self::admin_menu().
	 *
	 * @global $_POST.
	 */
	public function properties() {
		if ( !current_user_can( 'manage_options' ) )
			return;	// Except an administrator

		$show_reload = false;
		$message = '';
		if ( isset( $_POST['properties'] ) ) {
			check_admin_referer( self::LOGIN_REBUILDER_PROPERTIES_NAME.$this->_nonce_suffix() );

			if ( $this->_verify_private_nonce() ) {
				if ( isset( $_POST['test-notify'] ) ) {
					$this->_nofity_admin_login();
					$message .= __( "Please check your inbox for a confirmation email.", LOGIN_REBUILDER_DOMAIN );
				} else {
					$_POST['properties']['page'] = trim( $_POST['properties']['page'] );
					$_POST['properties']['page_subscriber'] = trim( $_POST['properties']['page_subscriber'] );
					if ( $this->_is_reserved_login_file( $_POST['properties']['page'] ) ) {
						$message = __( 'New login file is system file. Please change a path name.', LOGIN_REBUILDER_DOMAIN );
						$this->properties = $_POST['properties'];
					} else if ( $_POST['properties']['page'] != '' && $this->_case_subsite_invalid_login_file( $_POST['properties']['page'] ) ) {
						$message = __( 'The case of the sub-site, new login file is invalid. Please change a path name.', LOGIN_REBUILDER_DOMAIN );
						$this->properties = $_POST['properties'];
					} else if ( $_POST['properties']['page_subscriber'] != '' && ( $_POST['properties']['page_subscriber'] == $_POST['properties']['page'] || $this->_is_reserved_login_file( $_POST['properties']['page_subscriber'] ) ) ) {
						$message = __( 'Login file for subscriber is invalid. Please change a path name.', LOGIN_REBUILDER_DOMAIN );
						$this->properties = $_POST['properties'];
					} else if ( $_POST['properties']['page_subscriber'] != '' && $this->_case_subsite_invalid_login_file( $_POST['properties']['page_subscriber'] ) ) {
						$message = __( 'The case of the sub-site, login file for subscriber is invalid. Please change a path name.', LOGIN_REBUILDER_DOMAIN );
						$this->properties = $_POST['properties'];
					} else if ( $_POST['properties']['page_subscriber'] != '' && !( is_array( $_POST['properties']['secondary_roles'] ) && count( $_POST['properties']['secondary_roles'] ) > 0 ) ) {
						$message = __( 'User role to use the secondary login file is not selected. Please select at least one role.', LOGIN_REBUILDER_DOMAIN );
						$this->properties = $_POST['properties'];
					} else {
						$prev_status = $this->properties['status'];
						$prev_page = $this->properties['page'];
	
						$_ambiguous_error_message = isset( $_POST['properties']['ambiguous_error_message'] );
						$_disable_authenticate_email_password = isset( $_POST['properties']['disable_authenticate_email_password'] );
						$_reject_user_register = isset( $_POST['properties']['reject_user_register'] );
						$_contains_heading_line = isset( $_POST['properties']['contains_heading_line'] );
						$_notify_admin_login = isset( $_POST['properties']['notify_admin_login'] );
						
						$_logging_limit_invalid = isset( $_POST['properties']['logging_limit']['invalid'] )?
							intval( $_POST['properties']['logging_limit']['invalid'] ): self::LOGIN_REBUILDER_LOGGING_LIMIT;
						$_logging_limit_invalid = $this->_validate_logging_limit( $_logging_limit_invalid );
						$_logging_limit_login = isset( $_POST['properties']['logging_limit']['login'] )?
							intval( $_POST['properties']['logging_limit']['login'] ): self::LOGIN_REBUILDER_LOGGING_LIMIT;
						$_logging_limit_login = $this->_validate_logging_limit( $_logging_limit_login );

						$_access_author_page = isset( $_POST['properties']['access_author_page'] )?
							intval( $_POST['properties']['access_author_page'] ): self::LOGIN_REBUILDER_ACCESS_AUTHOR_PAGE_ACCEPT;

						$_oembed = isset( $_POST['properties']['oembed'] )?
							intval( $_POST['properties']['oembed'] ): self::LOGIN_REBUILDER_OEMBED_DEFAULT;

						$_use_lock_file = isset( $_POST['properties']['use_lock_file'] )?
							intval( $_POST['properties']['use_lock_file'] ): false;
						$_lock_file_path = trim( $_POST['properties']['lock_file_path'] );
						$_locked_status_popup = isset( $_POST['properties']['locked_status_popup'] )?
							intval( $_POST['properties']['locked_status_popup'] ): false;

						if ( $this->properties['keyword'] != $_POST['properties']['keyword'] ||
							$this->properties['logging'] != $_POST['properties']['logging'] ||
							$this->properties['page'] != $_POST['properties']['page'] ||
							$this->properties['page_subscriber'] != $_POST['properties']['page_subscriber'] ||
							$this->properties['secondary_roles'] != $_POST['properties']['secondary_roles'] ||

							$this->properties['logging_limit']['invalid'] != $_logging_limit_invalid ||
							$this->properties['logging_limit']['login'] != $_logging_limit_login ||

							$this->properties['ambiguous_error_message'] != $_ambiguous_error_message ||
							$this->properties['disable_authenticate_email_password'] != $_disable_authenticate_email_password ||
							$this->properties['reject_user_register'] != $_reject_user_register ||
							$this->properties['contains_heading_line'] != $_contains_heading_line ||
							$this->properties['notify_admin_login'] != $_notify_admin_login ||
							$this->properties['access_author_page'] != $_access_author_page ||
							$this->properties['oembed'] != $_oembed ||

							$this->properties['use_lock_file'] != $_use_lock_file ||
							$this->properties['lock_file_path'] != $_lock_file_path ||
							$this->properties['locked_status_popup'] != $_locked_status_popup
							) {
	
							$this->properties['logging'] = $_POST['properties']['logging'];
							$this->properties['secondary_roles'] = $_POST['properties']['secondary_roles'];

							$this->properties['logging_limit']['invalid'] = $_logging_limit_invalid;
							$this->properties['logging_limit']['login'] = $_logging_limit_login;

							$this->properties['ambiguous_error_message'] = $_ambiguous_error_message;
							$this->properties['disable_authenticate_email_password'] = $_disable_authenticate_email_password;
							$this->properties['reject_user_register'] = $_reject_user_register;
							$this->properties['contains_heading_line'] = $_contains_heading_line;
							$this->properties['notify_admin_login'] = $_notify_admin_login;

							$this->properties['access_author_page'] = $_access_author_page;
							$this->properties['oembed'] = $_oembed;

							$this->properties['use_lock_file'] = $_use_lock_file;
							$this->properties['lock_file_path'] = $_lock_file_path;
							$this->properties['locked_status_popup'] = $_locked_status_popup;

							if ( $this->properties['keyword'] != $_POST['properties']['keyword'] &&
								$this->use_site_option && is_multisite() ) {
								// subsite keyword update
								$sites = $this->_get_sites( get_current_blog_id() );
								if ( is_array( $sites ) ) 	foreach ( $sites as $site ) {
									switch_to_blog( $site->blog_id );
									$properties = get_option( LOGIN_REBUILDER_PROPERTIES, '' );
									if ( empty( $properties ) ) {
										$properties = array();
									}
									$properties['keyword'] = $_POST['properties']['keyword'];
									if ( isset( $properties['page'] ) && !empty( $properties['page'] ) ) {
										$login_path = $this->_login_file_path( $properties['page'] );
										if ( @file_exists( $login_path ) )
											$updated = $this->_update_login_file_keyword( $login_path, $properties['keyword'] );
									}
									if ( isset( $properties['page_subscriber'] ) && !empty( $properties['page_subscriber'] ) ) {
										$login_path = $this->_login_file_path( $properties['page_subscriber'] );
										if ( @file_exists( $login_path ) )
											$updated = $this->_update_login_file_keyword( $login_path, $properties['keyword'] );
									}
									update_option( LOGIN_REBUILDER_PROPERTIES, $properties );
									restore_current_blog();
								}
							}
							$this->properties['keyword'] = $_POST['properties']['keyword'];
	
							if ( $this->properties['page'] != $_POST['properties']['page'] ) {
								$login_path = $this->_login_file_path( $this->properties['page'] );
								if ( @ file_exists( $login_path ) && $this->_is_deletable( $login_path ) ) @ unlink( $login_path );
								$this->properties['page'] = $_POST['properties']['page'];
							}
							if ( $this->properties['page_subscriber'] != $_POST['properties']['page_subscriber'] ) {
								$login_path = $this->_login_file_path( $this->properties['page_subscriber'] );
								if ( @ file_exists( $login_path ) && $this->_is_deletable( $login_path ) ) @ unlink( $login_path );
								$this->properties['page_subscriber'] = $_POST['properties']['page_subscriber'];
							}
	
							$result = $this->_do_save( $_POST['properties'] );
							if ( $result['update'] ) {
								$this->properties['status'] = intval( $_POST['properties']['status'] );
							} else if ( ! empty( $this->properties['page'] ) && ( ! @ file_exists( $this->_login_file_path( $this->properties['page'] ) ) || !$this->_is_valid_new_login_file() ) ) {
								$message .= __( "However, failed to write a new login file to disk.\nPlease change into the enabled writing of a disk or upload manually.", LOGIN_REBUILDER_DOMAIN );
								$this->properties['status'] = self::LOGIN_REBUILDER_STATUS_IN_PREPARATION;
							}
							$subscriber = $_POST['properties'];
							$subscriber['page'] = $subscriber['page_subscriber'];
							$subscriber['content'] = $subscriber['content_subscriber'];
							$result = $this->_do_save( $subscriber );
							$message = __( 'Options saved.', LOGIN_REBUILDER_DOMAIN ).' ';
							if ( !$result['update'] && !empty( $this->properties['page_subscriber'] ) && ( !@file_exists( $this->_login_file_path( $this->properties['page_subscriber'] ) ) || !$this->_is_valid_new_login_file( $this->properties['page_subscriber'] ) ) ) {
								$message .= __( "However, failed to write a login file for subscriber to disk.\nPlease change into the enabled writing of a disk or upload manually.", LOGIN_REBUILDER_DOMAIN );
							}
						} else if ( $this->properties['status'] != intval( $_POST['properties']['status'] ) ) {
							$message = __( 'Options saved.', LOGIN_REBUILDER_DOMAIN ).' ';
							$this->properties['status'] = intval( $_POST['properties']['status'] );
							if ( $this->properties['status'] == self::LOGIN_REBUILDER_STATUS_WORKING ) {
								if ( !@file_exists( $this->_login_file_path( $this->properties['page'] ) ) ) {
									$result = $this->_do_save( $_POST['properties'] );
									if ( !$result['update'] ) {
										$message .= __( "However, a new login file was not found.", LOGIN_REBUILDER_DOMAIN );
										$this->properties['status'] = self::LOGIN_REBUILDER_STATUS_IN_PREPARATION;
									}
								} else if ( !$this->_is_valid_new_login_file() ) {
									$message .= __( "However, the contents of a new login file are not in agreement.", LOGIN_REBUILDER_DOMAIN );
									$this->properties['status'] = self::LOGIN_REBUILDER_STATUS_IN_PREPARATION;
								}
							}
						} else {
							$message = __( 'Options saved.', LOGIN_REBUILDER_DOMAIN ).' ';
						}
						$this->properties['response'] = intval( $_POST['properties']['response'] );
						$this->_save_option();

						// rewrite logout url
						if ( $this->properties['status'] == self::LOGIN_REBUILDER_STATUS_IN_PREPARATION ) {
							$logout_from = $this->_login_file_url( ( $prev_status == self::LOGIN_REBUILDER_STATUS_WORKING )? $prev_page: $this->properties['page'] );
							$logout_to = site_url().'/wp-login.php';
						} else {
							if ( $prev_status == self::LOGIN_REBUILDER_STATUS_WORKING )
								$logout_from = $this->_login_file_url( $prev_page );
							else
								$logout_from = site_url().'/wp-login.php';
							$logout_to = $this->_login_file_url( $this->properties['page'] );
						}
					}
					$this->_clear_private_nonce();
				}
			} else {
				$message .= __( "Expiration date of this page has expired.", LOGIN_REBUILDER_DOMAIN );
				$show_reload = true;
			}
		}
		$logging = $this->_get_logging();

		require_once 'includes/form-properties.php';
	}

	/**
	 * Check whether alternative login file can be written(AJAX: 'wp_ajax_login_rebuilder_try_save' filter).
	 *
	 * @since 1.0.0
	 * @since 2.0.0 Separated into '_do_save' function.
	 *
	 * @access public.
	 *
	 * @global DOING_AJAX, $_POST.
	 */
	public function try_save() {
		if ( !current_user_can( 'manage_options' ) || !( defined( 'DOING_AJAX' ) && DOING_AJAX ) || !isset( $_POST['page'] ) )
			wp_die( -1 );	// Except an administrator

		check_ajax_referer( self::LOGIN_REBUILDER_AJAX_NONCE_NAME.$this->_nonce_suffix() );

		extract( $_POST );
		$data = array(
			'request'=>$page,
			'path'=>$this->_login_file_path( $page ),
			'url'=>$this->_login_file_url( $page ),
			'exists'=>false,
			'writable'=>false,
			'update'=>false,
			'content'=>$this->_rewrite_login_content( $page, $this->content ) );
		// exists
		if ( @file_exists( $data['path'] ) )
			$data['exists'] = true;
		// writable
		if ( ( $fp = @fopen( $data['path'] , 'a' ) ) !== false ) {
			@fclose( $fp );
			if ( !$data['exists'] )
				@unlink( $data['path'] );
			$data['writable'] = true;
		}
		if ( function_exists( 'wp_send_json_success' ) )
			wp_send_json_success( $data );
		else {
			@header( 'Content-Type: application/json; charset=' . get_option( 'blog_charset' ) );
			echo json_encode( array( 'success'=>true, 'data'=>$data ) );
			exit;
		}
	}

	/**
	 * Save an alternative login file.
	 *
	 * @since 2.0.0
	 *
	 * @access private.
	 *
	 * @param array $param An array login data. 'page' and 'content' key required.
	 * @return array.
	 */
	private function _do_save( $param = null ) {
		$data = null;
		if ( current_user_can( 'manage_options' ) &&
			is_array( $param ) && count( $param ) > 0 &&
			isset( $param['page'] ) && isset( $param['content'] ) ) {
			extract( $param );
			$data = array(
					'request'=>$page,
					'path'=>$this->_login_file_path( $page ),
					'url'=>$this->_login_file_url( $page ),
					'exists'=>false,
					'writable'=>false,
					'update'=>false,
					'content'=>$this->_rewrite_login_content( $page, $this->content ) );
			// exists
			if ( @file_exists( $data['path'] ) )
				$data['exists'] = true;
			// writable
			if ( ( $fp = @fopen( $data['path'] , 'a' ) ) !== false ) {
				@fclose( $fp );
				if ( !$data['exists'] )
					@unlink( $data['path'] );
				$data['writable'] = true;
			}
			// update
			if ( ( $fp = @fopen( $data['path'], 'w' ) ) !== false ) {
				@fwrite( $fp, stripslashes( $content ) );
				@fclose( $fp );
				@chmod( $data['path'], 0644 );
				$data['update'] = true;
			}
		}
		return $data;
	}

	/**
	 * Check existence of lock file(AJAX: 'wp_ajax_login_rebuilder_lock_exists' filter).
	 *
	 * @since 2.5.0
	 *
	 * @access public.
	 *
	 * @global DOING_AJAX, $_POST.
	 */
	public function lock_exists() {
		if ( ! current_user_can( 'manage_options' ) || ! ( defined( 'DOING_AJAX' ) && DOING_AJAX ) || !isset( $_POST['path'] ) ) {
			wp_die( -1 );	// Except an administrator
		}

		check_ajax_referer( self::LOGIN_REBUILDER_AJAX_NONCE_NAME.$this->_nonce_suffix() );

		load_plugin_textdomain( LOGIN_REBUILDER_DOMAIN, false, plugin_basename( dirname( __FILE__ ) ).'/languages' );
		extract( $_POST );
		$path = trim( $path );
		$data = array(
				'path'		=> $path,
				'exists'	=> false,
				'color'		=> '',
				'status'	=> '',
		);
		$exists = false;
		if ( ! empty( $path ) && $exists = @ file_exists( $path ) ) {
			$data['exists'] = true;
			if ( $use ) {
				$data['color'] = 'red';
			} else {
				$data['color'] = 'orange';
			}
		}
		$data['status'] = $this->_lock_file_status( $use, $exists );
		if ( function_exists( 'wp_send_json_success' ) ) {
			wp_send_json_success( $data );
		} else {
			@ header( 'Content-Type: application/json; charset=' . get_option( 'blog_charset' ) );
			echo json_encode( array( 'success'=>true, 'data'=>$data ) );
			exit;
		}
	}

	/**
	 * Display message for properties page.
	 *
	 * @since 2.0.0
	 *
	 * @access private.
	 *
	 * @param string $message Update message text.
	 */
	private function _properties_message( $message ) {
		if ( !empty( $message ) ) {
			if ( $this->_is_wp_version( '3.5', '>=' ) ) { ?>
<div id="setting-error-settings_updated" class="updated settings-error"><p><strong><?php echo $message; ?></strong></p></div>
<?php		} else { ?>
<div id="message" class="update fade"><p><?php echo $message; ?></p></div>
<?php		}
		}
	}

	/**
	 * The initial value of properties.
	 *
	 * @since 1.3.0
	 * @since 1.4.0 Changed to '_default_properties' from 'default_properties' the name of this method.
	 *
	 * @access private.
	 *
	 * @return array.
	 */
	private function _default_properties() {
		$default_properties = array(
				'status'				=> self::LOGIN_REBUILDER_STATUS_IN_PREPARATION,
				'logging'				=> self::LOGIN_REBUILDER_LOGGING_OFF,
				'page'					=> $this->candidate[ array_rand( $this->candidate ) ],
				'page_subscriber'		=> '',
				'secondary_roles'		=> array( 'subscriber' ),
				'keyword'				=> $this->_generate_keyword(),
				'response'				=> self::LOGIN_REBUILDER_RESPONSE_403,
				// [2.0.0] for XML-RPC properties.
				'xmlrpc_enhanced'		=> false,
				'xmlrpc_disabled'		=> false,
				'limits_user'			=> false,
				'login_possible'		=> array(),
				'limits_method'			=> false,
				'active_method'			=> array(),
				'self_pingback'			=> false,
				'pingback_disabled'		=> false,
				'pingback_receive'		=> false,
				'receive_nsec'			=> 1,		// seconds
				'receive_per_sec'		=> 5,
				'refuses_to_accept'		=> 10,	// minutes
				'refuses_datetime'		=> 0,
				// [2.1.0]
				'ambiguous_error_message'				=> 0,
				'disable_authenticate_email_password'	=> 0,
				// [2.2.0]
				'reject_user_register'	=> 1,
				'notify_admin_login'	=> 0,
				// [2.5.0]
				'use_lock_file'			=> false,
				'lock_file_path'		=> '',
				'locked_status_popup'	=> false,
		);
		return $default_properties;
	}

	/**
	 * Load the value of properties.
	 *
	 * @since 1.3.0
	 * @since 1.4.0 Changed to '_load_option' from 'load_option' the name of this method.
	 *
	 * @access private.
	 */
	private function _load_option() {
		$default_properties = $this->_default_properties();
		$this->properties = get_site_option( LOGIN_REBUILDER_PROPERTIES, $default_properties );
		if ( ! isset( $this->properties['secondary_roles'] ) ) {
			$this->properties['secondary_roles'] = array( 'subscriber' );
		}
		if ( ! $this->use_site_option ) {
			$_properties = get_option( LOGIN_REBUILDER_PROPERTIES, $default_properties );
			if ( is_numeric( $_properties ) ) {
				$_properties = array_merge( $this->properties, array( 'status'=>$_properties ) );
			}
			$this->properties = $_properties;
		}
		if ( ! isset( $this->properties['logging'] ) ) {
			$this->properties['logging'] = self::LOGIN_REBUILDER_LOGGING_OFF;
		}
		if ( ! isset( $this->properties['xmlrpc_disabled'] ) ) {
			$this->properties['xmlrpc_enhanced']	= false;
			$this->properties['xmlrpc_disabled']	= false;
			$this->properties['limits_user']		= false;
			$this->properties['login_possible']		= array();
			$this->properties['limits_method']		= false;
			$this->properties['active_method']		= array();
			$this->properties['self_pingback']		= false;
			$this->properties['pingback_disabled']	= false;
			$this->properties['pingback_receive']	= false;
			$this->properties['receive_per_sec']	= 5;
			$this->properties['refuses_to_accept']	= 10;
			$this->properties['refuses_datetime']	= 0;
		}
		if ( ! isset( $this->properties['ambiguous_error_message'] ) ) {
			$this->properties['ambiguous_error_message'] = 0;
		}
		if ( ! isset( $this->properties['disable_authenticate_email_password'] ) ) {
			$this->properties['disable_authenticate_email_password'] = 0;
		}
		if ( ! isset( $this->properties['reject_user_register'] ) ) {	// [2.2.0]
			$this->properties['reject_user_register'] = 1;
		}
		if ( ! isset( $this->properties['notify_admin_login'] ) ) {		// [2.2.0]
			$this->properties['notify_admin_login'] = 0;
		}
		if ( ! isset( $this->properties['logging_limit'] ) ) {			// [2.3.0]
			$this->properties['logging_limit'] = array(
				'invalid'	=> self::LOGIN_REBUILDER_LOGGING_LIMIT,
				'login'		=> self::LOGIN_REBUILDER_LOGGING_LIMIT,
				'pingback'	=> self::LOGIN_REBUILDER_LOGGING_LIMIT,
			);
		}
		if ( ! isset( $this->properties['contains_heading_line'] ) ) {	// [2.3.0]
			$this->properties['contains_heading_line'] = true;
		}
		if ( ! isset( $this->properties['access_author_page'] ) ) {		// [2.4.0]
			$this->properties['access_author_page'] = 0;
		}
		if ( ! isset( $this->properties['oembed'] ) ) {					// [2.4.1]
			$this->properties['oembed'] = 0;
		}
		if ( ! isset( $this->properties['use_lock_file'] ) ) {			// [2.5.0]
			$this->properties['use_lock_file']			= false;
			$this->properties['lock_file_path']			= '';
			$this->properties['locked_status_popup']	= false;
		}
	}

	/**
	 * Save the value of properties.
	 *
	 * @since 1.3.0
	 * @since 1.4.0 Changed to '_save_option' from 'save_option' the name of this method.
	 *
	 * @access private.
	 */
	private function _save_option() {
		if ( $this->use_site_option )
			update_site_option( LOGIN_REBUILDER_PROPERTIES, $this->properties );
		else
			update_option( LOGIN_REBUILDER_PROPERTIES, $this->properties );
	}

	/**
	 * Generate a keyword which is a combination of alphanumeric characters.
	 *
	 * @since 1.3.0 Changed to '_raw_generate_keyword' from 'generate_keyword' the name of this method.
	 *
	 * @access private.
	 *
	 * @see self::_generate_keyword().
	 *
	 * @return string.
	 */
	private function _raw_generate_keyword() {
		return substr( str_shuffle( 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyz0123456789' ), rand( 0, 60 ), 8 );
	}

	/**
	 * Retrieve keyword for login page.
	 *
	 * @since 1.0.0
	 * @since 1.3.0 Divided the original function to '_raw_generate_keyword' method.
	 * @since 1.4.0 Changed to '_generate_keyword' from 'generate_keyword' the name of this method.
	 *
	 * @access private.
	 *
	 * @see self::_default_properties().
	 *
	 * @return string.
	 */
	private function _generate_keyword() {
		if ( $this->use_site_option )
			return $this->_raw_generate_keyword();
		else {
			// sub site
			$properties = get_site_option( LOGIN_REBUILDER_PROPERTIES, '' );
			if ( empty( $properties ) ) {
				$properties = $this->_default_properties();
				$properties['keyword'] = $this->_raw_generate_keyword();
				update_site_option( LOGIN_REBUILDER_PROPERTIES, $properties );
			}
			return $properties['keyword'];
		}
	}

	/**
	 * Compares WordPress version number strings.
	 *
	 * @since 2.0.0
	 *
	 * @access private.
	 *
	 * @global string $wp_version
	 *
	 * @param string $version Version number.
	 * @param string $compare Operator. Default is '>='.
	 * @return bool.
	 */
	private function _is_wp_version( $version, $compare = '>=' ) {
		return version_compare( $GLOBALS['wp_version'], $version, $compare );
	}

	/**
	 * Exclude invalid part from the url.
	 *
	 * @since 2.0.0
	 *
	 * @access private.
	 *
	 * @param string $url.
	 * @return string.
	 */
	private function _sanitize_url( $url ) {
		return preg_replace( '/[\s"\'\(<\[](.|\n)*$/', '', $url );
	}

	/**
	 * Retrieve date and time format for widgets.
	 *
	 * @since 1.4.4
	 *
	 * @access private.
	 *
	 * @return string.
	 */
	private function _date_time_format() {
		$date_format = __( 'M jS' );
		if ( $date_format == 'M jS' ) $date_format .= ',';
		return $date_format.' '.get_option( 'time_format' );
	}

	/**
	 * Retrieve initial log data.
	 *
	 * @since 2.0.0
	 *
	 * @return array.
	 */
	private function _init_logging() {
		return array( 'invalid'=>array(), 'login'=>array(), 'pingback'=>array() );
	}

	/**
	 * Retrieve the log data.
	 *
	 * @since 2.0.0
	 *
	 * @access private.
	 *
	 * @return array.
	 */
	private function _get_logging() {
		$logging = get_option( LOGIN_REBUILDER_LOGGING_NAME, '' );
		if ( empty( $logging ) ) {
			$logging = $this->_init_logging();
			add_option( LOGIN_REBUILDER_LOGGING_NAME, $logging, '', 'no' );
		}
		return $logging;
	}

	/**
	 * Update the log data.
	 *
	 * @since 2.0.0
	 *
	 * @access private.
	 *
	 * @param array  $logging List of logging data.
	 * @param string $type Log data type. If the data type is specified, the data exceeds the limit will be deleted.
	 */
	private function _update_logging( &$logging, $type = null ) {
		if ( !is_null( $type ) ) {
			if ( isset( $logging[$type] ) && is_array( $logging[$type] ) ) {
				$limit = isset( $this->properties['logging_limit'][$type] )?
					$this->properties['logging_limit'][$type]: self::LOGIN_REBUILDER_LOGGING_LIMIT;
				if ( count( $logging[$type] ) > $limit ) {
					$logging[$type] = array_slice( $logging[$type], ( count( $logging[$type] ) - $limit ), $limit );
				}
			} else
				$logging[$type] = array();
		}
		update_option( LOGIN_REBUILDER_LOGGING_NAME, $logging );
	}

	/**
	 * Delete the log data.
	 *
	 * @since 2.0.0
	 *
	 * @access private.
	 */
	private function _delete_logging() {
		delete_option( LOGIN_REBUILDER_LOGGING_NAME );
	}

	/**
	 * Add the log data.
	 *
	 * @since 1.4.0
	 * @since 2.0.0 Divided into _get_logging and _update_logging method.
	 *
	 * @access private.
	 *
	 * @param string $type Log data type ('invalid', 'login' and 'pingback').
	 * @param array  $log Log data.
	 */
	private function _logging( $type, $log ) {
		if ( is_array( $log ) ) {
			$logging = $this->_get_logging();
			$logging[$type][] = $log;
			$this->_update_logging( $logging, $type );
		}
	}

	/**
	 * Determines whether the user can use the secondary login page.
	 *
	 * @since 1.4.0
	 *
	 * @access private.
	 *
	 * @see self::site_url(), self::wp_redirect(), self::role_authenticate().
	 *
	 * @param WP_User $user.
	 * @return bool.
	 */
	private function _is_secondary_login_user( $user ) {
		if ( is_array( $user->roles ) ) foreach ( $user->roles as $role ) {
			if ( in_array( $role, (array)$this->properties['secondary_roles'] ) ) return true;
		}
		return false;
	}

	/**
	 * Check that the user can not use the secondary login page.
	 *
	 * @since 1.4.0
	 *
	 * @access private.
	 *
	 * @see self::role_authenticate().
	 *
	 * @global $wp_roles.
	 *
	 * @param WP_User $user.
	 * @return bool.
	 */
	private function _is_not_secondary_login_user( $user ) {
		if ( is_array( $user->roles ) ) {
			global $wp_roles;
			$not_secondary_roles = array_diff( array_keys( $wp_roles->roles ), (array)$this->properties['secondary_roles'] );
			foreach ( $user->roles as $role ) {
				if ( in_array( $role, $not_secondary_roles ) ) return true;
			}
		}
		return false;
	}

	/**
	 * Change the URL of the new login page if the URL contains a standard login page.
	 *
	 * @since 1.3.0
	 * @since 1.4.0 Changed to '_rewrite_login_url' from 'rewrite_login_url' the name of this method.
	 *
	 * @access private.
	 *
	 * @see self::site_url(), self::wp_redirect().
	 *
	 * @param string $wp_login URL of standard login page.
	 * @param string $page URL of new login page.
	 * @param string $url Requested URL.
	 * @return string.
	 */
	private function _rewrite_login_url( $wp_login, $page, $url ) {
		if ( strpos( $url, $wp_login ) !== false ) {
			$new_url = $this->_login_file_url( $page );
			if ( ( $pos = strpos( $url, '?' ) ) !== false )
				$new_url .= substr( $url, $pos );
			return $new_url;
		} else
			return $url;
	}

	/**
	 * Check whether the URL contains the login page.
	 *
	 * @since 1.3.0
	 * @since 1.4.0 Changed to '_in_url' from 'in_url' the name of this method.
	 *
	 * @access private.
	 *
	 * @see self::login_init(), self::site_url(), self::wp_redirect(), self::role_authenticate().
	 *
	 * @param string $url Requested URL.
	 * @param string $page URL of new login page.
	 * @return bool.
	 */
	private function _in_url( $url, $page ) {
		return ( strpos( $url, '/'.ltrim( $page , '/' ) ) !== false );
	}

	/**
	 * Retrieve the URL of the new login page.
	 *
	 * @since 1.3.0
	 * @since 1.4.0 Changed to '_login_file_url' from 'login_file_url' the name of this method.
	 *
	 * @access private.
	 *
	 * @see self::wp_secondary_login_url(), self::properties(), self::try_save(), self::_do_save(),
	 *      self::_rewrite_login_url().
	 *
	 * @param string $page URI of new login page.
	 * @return string.
	 */
	private function _login_file_url( $page ) {
		if ( strpos( $page, '/' ) !== false )
			return $this->root_url.'/'.ltrim( $page , '/' );
		else
			return site_url( $page );
	}

	/**
	 * Retrieve the PATH of the new login page.
	 *
	 * @since 1.3.0
	 * @since 1.4.0 Changed to '_login_file_path' from 'login_file_path' the name of this method.
	 *
	 * @access private.
	 *
	 * @see self::__construct(), self::properties(), self::try_save(), self::_do_save(),
	 *      self::_is_deletable(), self::_is_valid_new_login_file().
	 *
	 * @param string $page URI of new login page.
	 * @return string.
	 */
	private function _login_file_path( $page ) {
		if ( strpos( $page, '/' ) !== false )
			$path = $this->root_path.'/'.ltrim( $page , '/' );
		else
			$path = ABSPATH.$page;
		if ( function_exists( 'wp_normalize_path' ) )
			$path = wp_normalize_path( $path );
		return $path;
	}

	/**
	 * Create the content of the new login page.
	 *
	 * @since 1.3.0
	 * @since 1.4.0 Changed to '_rewrite_login_content' from 'rewrite_login_content' the name of this method.
	 *
	 * @access private.
	 *
	 * @see self::try_save(), self::_do_save(), self::_is_valid_new_login_file().
	 *
	 * @param string $page URI of new login page.
	 * @param string $content New login page content.
	 * @return string.
	 */
	private function _rewrite_login_content( $page, $content ) {
		if ( strpos( $page, '/' ) !== false ) {
			$wp_login = '';
			if ( defined( 'ABSPATH' ) && file_exists( ABSPATH.'wp-login.php' ) )
				$wp_login = ABSPATH.'wp-login.php';
			else if ( defined( 'WPINC' ) && file_exists( ABSPATH.WPINC.'/wp-login.php' ) )
				$wp_login = ABSPATH.WPINC.'/wp-login.php';
			if ( !empty( $wp_login ) ) {
				if ( function_exists( 'wp_normalize_path' ) )
					$wp_login = wp_normalize_path( $wp_login );
				$content = str_replace( './wp-login.php', $wp_login, $content );
			}
		}
		return $content;
	}

	/**
	 * Retrieve the information of the sub-site other than the current sub-site.
	 *
	 * @since 1.3.0
	 * @since 1.4.0 Changed to '_get_sites' from 'get_sites' the name of this method.
	 *
	 * @access private.
	 *
	 * @see self::properties(), self::_is_deletable().
	 *
	 * @global $wpdb;
	 *
	 * @param array $ignore_ids Array of ignore blog ids.
	 * @return array.
	 */
	private function _get_sites( $ignore_ids = null ) {
		if ( is_multisite() ) {
			global $wpdb;
			$query = "SELECT * FROM $wpdb->blogs WHERE 1=1";
			if ( !empty( $ignore_ids ) )
				$query .= " AND blog_id NOT IN (".implode( ',', (array)$ignore_ids ).")";
			return $wpdb->get_results( $query );
		} else
			return array();
	}

	/**
	 * Check whether the login page can be delete.
	 *
	 * @since 1.3.0
	 * @since 1.4.0 Changed to '_is_deletable' from 'is_deletable' the name of this method.
	 *
	 * @access private.
	 *
	 * @see self::properties().
	 *
	 * @param string $path URI of new login page.
	 * @return bool.
	 */
	private function _is_deletable( $path ) {
		if ( $this->_is_reserved_login_file( basename( $path ) ) ) return false;
		if ( !$this->use_site_option ) {
			$sites = $this->_get_sites( get_current_blog_id() );
			if ( is_array( $sites ) ) foreach ( $sites as $site ) {
				switch_to_blog( $site->blog_id );
				$properties = get_option( LOGIN_REBUILDER_PROPERTIES, '' );
				if ( isset( $properties['page'] ) && !empty( $properties['page'] ) ) {
					$login_path = $this->_login_file_path( $properties['page'] );
					if ( $login_path == $path ) return false;
				}
				if ( isset( $properties['page_subscriber'] ) && !empty( $properties['page_subscriber'] ) ) {
					$login_path = $this->_login_file_path( $properties['page_subscriber'] );
					if ( $login_path == $path ) return false;
				}
				restore_current_blog();
			}
		}
		return true;
	}

	/**
	 * Update the keyword that is included in the login page.
	 *
	 * @since 1.3.0
	 * @since 1.4.0 Changed to '_update_login_file_keyword' from 'update_login_file_keyword' the name of this method.
	 *
	 * @access private.
	 *
	 * @see self::properties().
	 *
	 * @param string $login_path URI of new login page.
	 * @param string $new_keyword New login page keyword.
	 * @return bool.
	 */
	private function _update_login_file_keyword( $login_path, $new_keyword ) {
		$updated = false;
		$content = @file_get_contents( $login_path );
		if ( $content !== false && ( $fp = @fopen( $login_path, 'w' ) ) !== false ) {
			$content = preg_replace( "/'LOGIN_REBUILDER_SIGNATURE', '[0-9a-zA-Z]+'/u", "'LOGIN_REBUILDER_SIGNATURE', '{$new_keyword}'", $content );
			@fwrite( $fp, $content );
			@fclose( $fp );
			$updated = true;
		}
		return $updated;
	}

	/**
	 * Check reserved file name.
	 *
	 * @since 1.0.0
	 * @since 1.4.0 Changed to '_is_reserved_login_file' from 'is_reserved_login_file' the name of this method.
	 *
	 * @access private.
	 *
	 * @see self::properties(), self::_is_deletable().
	 *
	 * @param string $filename File name for the new login page.
	 * @return bool.
	 */
	private function _is_reserved_login_file( $filename ) {
		return in_array( $filename,
				array( 'index.php', 'wp-activate.php', 'wp-app.php', 'wp-atom.php', 'wp-blog-header.php',
					'wp-comments-post.php', 'wp-commentsrss2.php', 'wp-config.php', 'wp-config-sample.php', 'wp-cron.php',
					'wp-feed.php', 'wp-links-opml.php', 'wp-load.php', 'wp-login.php', 'wp-mail.php',
					'wp-pass.php', 'wp-rdf.php', 'wp-register.php', 'wp-rss.php', 'wp-rss2.php',
					'wp-settings.php', 'wp-signup.php', 'wp-trackback.php', 'xmlrpc.php' ) );
	}

	/**
	 * Check whether effective as the login page.
	 *
	 * @since 1.0.0
	 * @since 1.4.0 Changed to '_is_valid_new_login_file' from 'is_valid_new_login_file' the name of this method.
	 *
	 * @access private.
	 *
	 * @see self::__construct(), self::role_authenticate(), self::properties().
	 *
	 * @param string $filename File name for the new login page.
	 * @return bool.
	 */
	private function _is_valid_new_login_file( $filename = null ) {
		if ( is_null( $filename ) )
			$filename = $this->properties['page'];
		return
			preg_replace( "/\r\n|\r|\n/", "\r", $this->_rewrite_login_content( $filename, str_replace( '%sig%', $this->properties['keyword'], $this->content ) ) ) ==
			preg_replace( "/\r\n|\r|\n/", "\r", trim( @file_get_contents( $this->_login_file_path( $filename ) ) ) );
	}

	/**
	 * Check whether invalid as the login page for the sub-site.
	 *
	 * @since 1.3.0
	 * @since 1.4.0 Changed to '_case_subsite_invalid_login_file' from 'case_subsite_invalid_login_file' the name of this method.
	 *
	 * @access private.
	 *
	 * @see self::properties().
	 *
	 * @param string $filename PATH of new login page.
	 * @return bool.
	 */
	private function _case_subsite_invalid_login_file( $filename ) {
		if ( empty( $finename ) ) return false;
		if ( $this->use_site_option ) return false;
		return ( strpos( $filename, '/' ) !== false );
	}

	/**
	 * Retrieve unique text for nonce key.
	 *
	 * @since 1.3.0
	 * @since 1.4.0 Changed to '_nonce_suffix' from 'nonce_suffix' the name of this method.
	 *
	 * @access private.
	 *
	 * @see self::properties(), self::try_save(), self::_private_nonce_field(), self::xmlrpc_properties().
	 *
	 * @return string.
	 */
	private function _nonce_suffix() {
		return date_i18n( 'His TO', filemtime( __FILE__ ) );
	}

	/**
	 * Prepare the private nonce field.
	 *
	 * @since 1.2.1
	 * @since 1.4.0 Changed to '_init_private_nonce' from 'init_private_nonce' the name of this method.
	 *
	 * @access private.
	 *
	 * @see self::_private_nonce_field().
	 */
	private function _init_private_nonce() {
		if ( get_option( self::LOGIN_REBUILDER_NONCE_NAME, '' ) == '' ) {
			add_option( self::LOGIN_REBUILDER_NONCE_NAME,
					array( get_current_user_id()=>array( 'nonce'=>'', 'access'=>time() ) ),
					'', 'no' );
		}
	}

	/**
	 * Clear the private nonce data.
	 *
	 * @since 1.2.3
	 * @since 1.4.0 Changed to '_clear_private_nonce' from 'clear_private_nonce' the name of this method.
	 *
	 * @access private.
	 *
	 * @see self::properties(), self::_init_private_nonce().
	 */
	private function _clear_private_nonce() {
		$private_nonce = get_option( self::LOGIN_REBUILDER_NONCE_NAME, '' );
		if ( isset( $private_nonce['nonce'] ) ) unset( $private_nonce['nonce'] );
		if ( isset( $private_nonce['access'] ) ) unset( $private_nonce['access'] );
		$user_id = get_current_user_id();
		if ( isset( $private_nonce[$user_id] ) ) {
			unset( $private_nonce[$user_id] );
			update_option( self::LOGIN_REBUILDER_NONCE_NAME, $private_nonce );
		}
	}

	/**
	 * Delete the private nonce data.
	 *
	 * @since 1.2.1
	 * @since 1.4.0 Changed to '_delete_private_nonce' from 'delete_private_nonce' the name of this method.
	 *
	 * @access private.
	 *
	 * @see self::deactivation(), self::_init_private_nonce().
	 */
	private function _delete_private_nonce() {
		delete_option( self::LOGIN_REBUILDER_NONCE_NAME );
	}

	/**
	 * Display the private nonce field.
	 *
	 * @since 1.2.1
	 * @since 1.4.0 Changed to '_private_nonce_field' from 'private_nonce_field' the name of this method.
	 *
	 * @access private.
	 *
	 * @see self::properties().
	 */
	private function _private_nonce_field( $field_name = self::LOGIN_REBUILDER_NONCE_NAME, $action = self::LOGIN_REBUILDER_NONCE_NAME ) {
		$field_name = esc_attr( $field_name );
		$now = time();
		$user_id = get_current_user_id();

		$this->_init_private_nonce();
		$private_nonce = get_option( self::LOGIN_REBUILDER_NONCE_NAME, '' );
		if ( isset( $private_nonce[$user_id]['nonce'] ) && $private_nonce[$user_id]['nonce'] != '' &&
			( $now-$private_nonce[$user_id]['access'] ) < self::LOGIN_REBUILDER_NONCE_LIFETIME/10*9 ) {
			// Do not update the nonce value.
			$nonce = $private_nonce[$user_id]['nonce'];
		} else {
			$nonce = wp_create_nonce( $action.($now%10000).$this->_nonce_suffix() );
			$private_nonce[$user_id] = array( 'nonce'=>$nonce, 'access'=>$now );
			update_option( self::LOGIN_REBUILDER_NONCE_NAME, $private_nonce );
		}
		$nonce_field = '<input type="hidden" id="'.$field_name.'" name="'.$field_name.'" value="'.$nonce.'" />';
		echo $nonce_field;
	}

	/**
	 * Verify the private nonce field.
	 *
	 * @since 1.2.1
	 * @since 1.4.0 Changed to '_verify_private_nonce' from 'verify_private_nonce' the name of this method.
	 *
	 * @access private.
	 *
	 * @see self::properties().
	 *
	 * @global $_REQUEST.
	 */
	private function _verify_private_nonce( $field_name = self::LOGIN_REBUILDER_NONCE_NAME, $lifetime = self::LOGIN_REBUILDER_NONCE_LIFETIME ) {
		$user_id = get_current_user_id();
		$valid = false;
		$field_name = esc_attr( $field_name );
		$now = time();
		$private_nonce = get_option( self::LOGIN_REBUILDER_NONCE_NAME, '' );
		if ( isset( $private_nonce[$user_id]['nonce'] ) && isset( $private_nonce[$user_id]['access'] ) &&
			isset( $_REQUEST[$field_name] ) && $_REQUEST[$field_name] == $private_nonce[$user_id]['nonce'] &&
			( $now-$private_nonce[$user_id]['access'] ) > 0 && ( $now-$private_nonce[$user_id]['access'] ) <= $lifetime ) {
			$valid = true;
		}
		return $valid;
	}

	/**
	 * The log of invalid access to the wp-login.php widget display.
	 *
	 * Version 1.4.3 and earlier, this feature is included in the properties method.
	 *
	 * @since 1.4.4
	 * @since 2.0.0 When log is XML-RPC request, the mark is indicated.
	 *
	 * @access private.
	 *
	 * @see self::meta_box_log_of_invalid_request()
	 */
	private function _view_log_of_invalid_request( $log_invalid ) {
		$gmt_offset = get_option( 'gmt_offset' );
		$date_time_format = $this->_date_time_format();
?>
<div id="invalid-log-title" ><?php
_e( "Request datetime - Username(Requesting IP)", LOGIN_REBUILDER_DOMAIN );
if ( current_user_can( 'manage_options' ) ) $this->_download_log_form( 'invalid' );
?></div>
<div id="invalid-log" style="<?php esc_attr_e( self::LOG_BOX_STYLES ); ?>">
<?php
		foreach ( $log_invalid as $log ) {
			echo esc_html( date_i18n( $date_time_format, $log['time']+$gmt_offset*3600 ) ).' - '.esc_html( $log['id'].'('.$log['ip'].')' );
			if ( isset( $log['xmlrpc'] ) && $log['xmlrpc'] === true )
				echo '(XMLRPC)';
?><br />
<?php
		}
?>
</div>
<div id="invalid-log-notice" ><?php _e( 'Notice', LOGIN_REBUILDER_DOMAIN ); ?>: <?php _e( "It will display the '(XMLRPC)' In the case of XML-RPC request.", LOGIN_REBUILDER_DOMAIN ); ?></div>
<?php
	}

	/**
	 * The log of login widget display.
	 *
	 * Version 1.4.3 and earlier, this feature is included in the properties method.
	 *
	 * @since 1.4.4
	 * @since 2.5.0 Add lock file status.
	 *
	 * @access private.
	 *
	 * @see self::meta_box_log_of_login()
	 */
	private function _view_log_of_login( $log_login ) {
		$gmt_offset = get_option( 'gmt_offset' );
		$date_time_format = $this->_date_time_format();
		$users = array();
?>
<div id="login-log-title" ><?php
_e( "Request datetime - Username(Requesting IP)", LOGIN_REBUILDER_DOMAIN );
if ( current_user_can( 'manage_options' ) ) $this->_download_log_form( 'login' );
?></div>
<div id="login-log" style="<?php esc_attr_e( self::LOG_BOX_STYLES  ); ?>">
<?php
		foreach ( $log_login as $log ) {
			if ( isset( $users[$log['id']] ) ) {
				$_user = $users[$log['id']];
			} else {
				$_user = get_user_by( 'id', $log['id'] );
				if ( !isset( $_user->user_nicename ) )
					$_user = (object)array( 'user_nicename'=>'@'.$log['id'] );
				$users[$log['id']] = $_user;
			}
			echo esc_html( date_i18n( $date_time_format, $log['time']+$gmt_offset*3600 ) ).' - '.esc_html( urldecode( $_user->user_nicename ).'('.$log['ip'].')' );
?><br />
<?php
		}
?>
</div>
<?php
if ( $this->properties['use_lock_file'] && ! empty( $this->properties['lock_file_path'] ) ) {
	$exists = @ file_exists( $this->properties['lock_file_path'] );
	$status = $this->_lock_file_status( true, $exists );
	$color = $exists? 'red': 'orange';
?>
<div id="login-lock-status" class="activity-block"><?php _e( 'Lock file', LOGIN_REBUILDER_DOMAIN ); ?> : <?php echo esc_html( basename( $this->properties['lock_file_path'] ) ); ?>&nbsp;<span style="color: <?php echo esc_attr( $color ); ?>;">[<?php echo esc_html( $status ); ?>]</span></div>
<?php }
	}

	/**
	 * The log of pingback widget display.
	 *
	 * @since 2.0.0
	 *
	 * @access private.
	 *
	 * @see self::meta_box_log_of_pingback()
	 */
	private function _view_log_of_pingback( $log_pingback ) {
		$gmt_offset = get_option( 'gmt_offset' );
		$date_time_format = $this->_date_time_format();
?><p><?php _e( 'Status' ); ?>: <?php
		if ( isset( $this->properties['refuses_datetime'] ) && !empty( $this->properties['refuses_datetime'] ) ) {
			echo '<span style="color: #CC0000;">'.sprintf( __( "It rejects the reception from %s", LOGIN_REBUILDER_DOMAIN ), date_i18n( 'H:i', $this->properties['refuses_datetime']+$gmt_offset*3600 ) ).'</span>';
		} else {
			_e( 'Accepting', LOGIN_REBUILDER_DOMAIN );
		}
?></p>
<div id="pingback-log-title" ><?php
_e( "Request datetime - Requesting IP|Status|From Hostname|(Error)", LOGIN_REBUILDER_DOMAIN );
if ( current_user_can( 'manage_options' ) ) $this->_download_log_form( 'pingback' );
?></div>
<div id="pingback-log" style="<?php esc_attr_e( self::LOG_BOX_STYLES  ); ?>">
<?php
		foreach ( $log_pingback as $log ) {
			if ( preg_match( '#^https?://([^:/]+)(:[0-9]+)?/(.+)$#', $log['from'], $matches ) )
				$from_hostname = $matches[1];
			else
				$from_hostname = __( '(Unknown)', LOGIN_REBUILDER_DOMAIN );
			$prefix = ( $log['status'] == self::PINGBACK_RECEIVE_STATUS_REFUSE )? '<span style="color: #CC0000;">': '<span>';
			$out = sprintf( "%s - %s %s %s", esc_html( date_i18n( $date_time_format, $log['time']+$gmt_offset*3600 ) ), esc_html( $log['ip'] ), esc_html( $this->_pingback_status( $log['status'] ) ), esc_html( $from_hostname ) );
			if ( isset( $log['error'] ) && is_array( $log['error'] ) ) {
				$out .= ' ('.$log['error']['code'].')';
			}
			echo $prefix.$out.'</span><br />';
		}
?>
</div>
<div id="pingback-log-notice" ><?php _e( 'Notice', LOGIN_REBUILDER_DOMAIN ); ?>: <?php _e( "'A' is accept.", LOGIN_REBUILDER_DOMAIN ); ?> <span style="color: #CC0000;"><?php _e( "'R' is refuse.", LOGIN_REBUILDER_DOMAIN ); ?></span></div>
<?php
	}

	/**
	 * Retrieve status text of pingback log.
	 *
	 * @since 2.0.0
	 *
	 * @access private.
	 *
	 * @see self::_view_log_of_pingback()
	 *
	 * @param int $status.
	 * @return string 'A' is accept, 'R' is refuse.
	 */
	private function _pingback_status( $status ) {
		$text = '-';
		switch ( $status ) {
			case self::PINGBACK_RECEIVE_STATUS_ACCEPT:
				return 'A';
				break;
			case self::PINGBACK_RECEIVE_STATUS_REFUSE:
				return 'R';
				break;
			default:
				break;
		}
		return $text;
	}

	/**
	 * XML-RPC properties page.
	 *
	 * @since 2.0.0
	 *
	 * @access public.
	 *
	 * @see self::admin_menu()
	 *
	 * @global $_POST.
	 */
	public function xmlrpc_properties() {
		if ( !current_user_can( 'manage_options' ) )
			return;	// Except an administrator

		$users = get_users( array( 'orderby'=>'ID', 'order'=>'ASC' ) );
		$_methods = array(	// see wp-includes/class-wp-xmlrpc-server.php @WordPress 4.4.0
				// WordPress API
				'wp.getUsersBlogs','wp.newPost','wp.editPost','wp.deletePost','wp.getPost','wp.getPosts',
				'wp.newTerm','wp.editTerm',	'wp.deleteTerm','wp.getTerm','wp.getTerms','wp.getTaxonomy','wp.getTaxonomies',
				'wp.getUser','wp.getUsers','wp.getProfile','wp.editProfile',
				'wp.getPage','wp.getPages','wp.newPage','wp.deletePage','wp.editPage','wp.getPageList','wp.getAuthors',
				'wp.getCategories','wp.getTags','wp.newCategory','wp.deleteCategory','wp.suggestCategories',
				'wp.uploadFile','wp.deleteFile',
				'wp.getCommentCount','wp.getPostStatusList','wp.getPageStatusList','wp.getPageTemplates',
				'wp.getOptions','wp.setOptions',
				'wp.getComment','wp.getComments','wp.deleteComment','wp.editComment','wp.newComment','wp.getCommentStatusList',
				'wp.getMediaItem','wp.getMediaLibrary','wp.getPostFormats','wp.getPostType','wp.getPostTypes','wp.getRevisions','wp.restoreRevision',
				// PingBack
				'pingback.ping', 'pingback.extensions.getPingbacks',
				// Blogger API
				'blogger.getUsersBlogs','blogger.getUserInfo','blogger.getPost','blogger.getRecentPosts','blogger.newPost','blogger.editPost','blogger.deletePost',
				// MetaWeblog API (with MT extensions to structs)
				'metaWeblog.newPost','metaWeblog.editPost','metaWeblog.getPost','metaWeblog.getRecentPosts','metaWeblog.getCategories','metaWeblog.newMediaObject',
				// MetaWeblog API aliases for Blogger API
				'metaWeblog.deletePost','metaWeblog.getUsersBlogs',
				// MovableType API
				'mt.getCategoryList','mt.getRecentPostTitles','mt.getPostCategories','mt.setPostCategories','mt.supportedMethods',	'mt.supportedTextFilters','mt.getTrackbackPings','mt.publishPost',
				// Other
				'demo.sayHello','demo.addTwoNumbers'
		);

		$caution_number = array();
		$message = '';
		if ( isset( $_POST['properties'] ) ) {
			check_admin_referer( self::XMLRPC_PROPERTIES_NAME.$this->_nonce_suffix() );

			$this->properties['xmlrpc_enhanced'] = intval( $_POST['properties']['xmlrpc_enhanced'] );
			$this->properties['xmlrpc_disabled'] = ( isset( $_POST['properties']['xmlrpc_disabled'] ) && $_POST['properties']['xmlrpc_disabled'] );
			$this->properties['self_pingback'] = ( isset( $_POST['properties']['self_pingback'] ) && $_POST['properties']['self_pingback'] );
			$this->properties['pingback_disabled'] = ( isset( $_POST['properties']['pingback_disabled'] ) && $_POST['properties']['pingback_disabled'] );
			$this->properties['pingback_receive'] = ( isset( $_POST['properties']['pingback_receive'] ) && $_POST['properties']['pingback_receive'] );

			$this->properties['limits_user'] = ( isset( $_POST['properties']['limits_user'] ) && $_POST['properties']['limits_user'] );
			$this->properties['login_possible'] = array();
			if ( isset( $_POST['properties']['login_possible'] ) && is_array( $_POST['properties']['login_possible'] ) ) foreach ( $_POST['properties']['login_possible'] as $_username ) {
				foreach ( $users as $_user ) {
					if ( $_user->user_login == $_username ) {
						$this->properties['login_possible'][] = $_username;
						break;
					}
				}
			}

			$this->properties['limits_method'] = ( isset( $_POST['properties']['limits_method'] ) && $_POST['properties']['limits_method'] );
			$this->properties['active_method'] = array();
			if ( isset( $_POST['properties']['active_method'] ) && is_array( $_POST['properties']['active_method'] ) ) foreach ( $_POST['properties']['active_method'] as $_methodname ) {
				if ( in_array( $_methodname, $_methods ) )
					$this->properties['active_method'][] = $_methodname;
			}

			if ( isset( $_POST['properties']['receive_per_sec'] ) && preg_match( '/^[0-9]+$/u', $_POST['properties']['receive_per_sec'] ) ) {
				$this->properties['receive_per_sec'] = intval( $_POST['properties']['receive_per_sec'] );
				if ( $this->properties['receive_per_sec'] < 1 ) {
					$message = __( 'Please specify a value of 1 or more.', LOGIN_REBUILDER_DOMAIN );
					$caution_number[] = 'receive_per_sec';
				}
			}
			if ( isset( $_POST['properties']['receive_nsec'] ) && preg_match( '/^[0-9]+$/u', $_POST['properties']['receive_nsec'] ) ) {
				$this->properties['receive_nsec'] = intval( $_POST['properties']['receive_nsec'] );
				if ( $this->properties['receive_nsec'] < 1 ) {
					$message = __( 'Please specify a value of 1 or more.', LOGIN_REBUILDER_DOMAIN );
					$caution_number[] = 'receive_nsec';
				}
			}
			if ( isset( $_POST['properties']['refuses_to_accept'] ) && preg_match( '/^[0-9]+$/u', $_POST['properties']['refuses_to_accept'] ) ) {
				$this->properties['refuses_to_accept'] = intval( $_POST['properties']['refuses_to_accept'] );
				if ( $this->properties['refuses_to_accept'] < 1 ) {
					$message = __( 'Please specify a value of 1 or more.', LOGIN_REBUILDER_DOMAIN );
					$caution_number[] = 'refuses_to_accept';
				}
			}

			if ( $_POST['submit'] == __( 'Acceptance resumes', LOGIN_REBUILDER_DOMAIN ) ) {
				$this->properties['refuses_datetime'] = 0;
				$this->_save_option();
				$message = __( 'Resumed the reception of the pingback.', LOGIN_REBUILDER_DOMAIN ).' ';
			} else if ( empty( $message ) ) {
				$this->_save_option();
				$message = __( 'Options saved.', LOGIN_REBUILDER_DOMAIN ).' ';
			}
		}

		$methods = array();
		foreach ( $_methods as $_method ) {
			@list( $_prefix, $_name ) = explode( '.', $_method );
			$methods[$_prefix][] = $_method;
		}

		require_once 'includes/form-xmlrpc-properties.php';
	}

	/**
	 * To limit the users who can authenticate with the XML-RPC request. ('authenticate' filter)
	 *
	 * @since 2.0.0
	 *
	 * @access public.
	 *
	 * @see self::_xmlrpc_actions().
	 *
	 * @param null|WP_User $user     User to authenticate.
	 * @param string       $username User login.
	 * @param string       $password User password
	 * @return null|WP_User|WP_Error User to authenticate.
	 */
	public function xmlrpc_authenticate( $user, $username, $password ) {
		if ( in_array( $username, $this->properties['login_possible'] ) )
			return $user;
		else
			return null;
	}

	/**
	 * To Limit the XML-RPC methods. ('xmlrpc_methods' filter)
	 *
	 * @since 2.0.0
	 *
	 * @access public.
	 *
	 * @see self::_xmlrpc_actions(), wp_xmlrpc_server::__construct().
	 *
	 * @param array $methods An array of XML-RPC methods.
	 * @return array.
	 */
	public function xmlrpc_methods( $methods ) {
		foreach ( $methods as $name=>$function ) {
			if ( !in_array( $name, $this->properties['active_method'] ) ) unset( $methods[$name] );
		}
		return $methods;
	}

	/**
	 * Exclude 'pingback.ping' from the XML-RPC methods. ('xmlrpc_methods' filter)
	 *
	 * @since 2.0.0
	 *
	 * @access public.
	 *
	 * @see self::_xmlrpc_actions(), wp_xmlrpc_server::__construct().
	 *
	 * @param array $methods An array of XML-RPC methods.
	 * @return array.
	 */
	public function pingback_disabled( $methods ) {
		if ( isset( $methods['pingback.ping'] ) ) unset( $methods['pingback.ping'] );
		return $methods;
	}

	/**
	 * Exclude pingback to this site from this site. ('pre_ping' action)
	 *
	 * @since 2.0.0
	 *
	 * @access public.
	 *
	 * @see self::_xmlrpc_actions(), pingback().
	 *
	 * @param array &$post_links An array of post links to be checked, passed by reference.
	 * @param array &$pung       Whether a link has already been pinged, passed by reference.
	 * @param int   $post_ID     The post ID.
	 */
	public function self_post_no_ping( &$post_links, &$pung, $post_ID ) {
		@list( $scheme, $siteurl ) = explode( ':', get_option( 'siteurl' ) );
		foreach ( $post_links as $i=>$link ) {
			if ( strpos( $link, '?' ) !== false )
				@list( $link_path, $link_args ) = explode( '?', $link );
			else
				$link_path = $link;
			if ( strpos( $link_path, $siteurl ) !== false )
				unset( $post_links[$i] );
		}
	}

	/**
	 * Pingback logging. ('pingback_ping_source_uri' filter)
	 *
	 * To disable in the case of a pingback from this site.
	 * To disable the excess pingback if you are receiving the number of restrictions.
	 *
	 * @since 2.0.0
	 *
	 * @access public.
	 *
	 * @see self::_xmlrpc_actions()
	 *
	 * @param string $pagelinkedfrom URI of the page linked from.
	 * @param string $pagelinkedto   URI of the page linked to.
	 * @return string.
	 */
	public function pingback_logging( $pagelinkedfrom, $pagelinkedto ) {
		$logging = $this->_get_logging();

		// pingback log data
		$refuse = false;
		$log = array(
				'time'=>microtime( true ),
				'ip'=>$this->remote_addr,
				'from'=>$this->_sanitize_url( $pagelinkedfrom ),
				'to'=>$this->_sanitize_url( $pagelinkedto ),
				'status'=>self::PINGBACK_RECEIVE_STATUS_ACCEPT );
		if ( $this->properties['self_pingback'] &&
			preg_match( '#^https?://([^:/]+)(:[0-9]+)?/(.+)$#', $pagelinkedfrom, $matches ) && $matches[1] == $_SERVER['SERVER_NAME'] ) {
			// $matches[1] hostname, [2] port, [3] uri
			$refuse = true;
		}
		if ( $this->properties['pingback_receive'] ) {
			if ( isset( $this->properties['refuses_datetime'] ) && !empty( $this->properties['refuses_datetime'] ) ) {
				$refuse = true;
			} else if ( count( $logging['pingback'] ) >= $this->properties['receive_per_sec'] ) {
				$recent_log_key = count( $logging['pingback'] )-$this->properties['receive_per_sec'];
				if ( microtime( true )-$logging['pingback'][$recent_log_key]['time'] < (float)$this->properties['receive_nsec'] ) {
					if ( !isset( $this->properties['refuses_datetime'] ) || empty( $this->properties['refuses_datetime'] ) ) {
						$this->properties['refuses_datetime'] = time();
						$this->_save_option();
					}
					$refuse = true;
				}
			}
		}
		if ( $refuse ) {
			// Do not process this data
			$log['status'] = self::PINGBACK_RECEIVE_STATUS_REFUSE;
			$pagelinkedfrom = '';
		}
		$logging['pingback'][] = $log;
		$this->_update_logging( $logging, 'pingback' );
		return $pagelinkedfrom;
	}

	/**
	 * Pingback error logging. ('xmlrpc_pingback_error' filter)
	 *
	 * @since 2.0.0
	 *
	 * @access public.
	 *
	 * @see self::_xmlrpc_actions()
	 *
	 * @param IXR_Error $ixr_error XML-RPC pingback error.
	 * @return IXR_Error.
	 */
	public function pingback_error_logging( $ixr_error ) {
		$logging = $this->_get_logging();
		$log = array_pop( $logging['pingback'] );
		$log['error'] = (array)$ixr_error;
		$logging['pingback'][] = $log;
		$this->_update_logging( $logging, 'pingback' );
		return $ixr_error;
	}

	/**
	 * Sets actions for the XML-RPC.
	 *
	 * @since 2.0.0
	 *
	 * @access private.
	 *
	 * @see self::__construct().
	 *
	 * @global XMLRPC_REQUEST.
	 */
	private function _xmlrpc_actions() {
		if ( isset( $this->properties['xmlrpc_enhanced'] ) && $this->properties['xmlrpc_enhanced'] ) {
			if ( $this->properties['xmlrpc_disabled'] )
				add_filter( 'xmlrpc_enabled', '__return_false', 9999, 1 );
			if ( defined( 'XMLRPC_REQUEST' ) && XMLRPC_REQUEST && $this->properties['limits_user'] )
				add_filter( 'authenticate', array( &$this, 'xmlrpc_authenticate' ), 9999, 3 );
			if ( $this->properties['limits_method'] )
				add_filter( 'xmlrpc_methods', array( &$this, 'xmlrpc_methods' ) );
			if ( $this->properties['self_pingback'] )
				add_action( 'pre_ping', array( &$this, 'self_post_no_ping' ), 10, 3 );
			if ( $this->properties['pingback_disabled'] )
				add_filter( 'xmlrpc_methods', array( &$this, 'pingback_disabled' ) );
			if ( $this->_is_wp_version( '3.6', '>=' ) ) {
				if ( isset( $this->properties['refuses_datetime'] ) && !empty( $this->properties['refuses_datetime'] ) &&
					( time() - $this->properties['refuses_datetime'] ) > $this->properties['refuses_to_accept']*60 ) {
					$this->properties['refuses_datetime'] = 0;
					$this->_save_option();
				}
				add_filter( 'pingback_ping_source_uri', array( &$this, 'pingback_logging' ), 10, 2 );
				add_filter( 'xmlrpc_pingback_error', array( &$this, 'pingback_error_logging' ), 10, 1 );
			}
		}
	}

	/**
	 * Authenticate error( Invalid username or incorrect password ).
	 *
	 * @since 2.1.0
	 *
	 * @access private.
	 *
	 * @see WP_Error.
	 * @see wp_authenticate.
	 *
	 * @return null|WP_User|WP_Error User to authenticate.
	 */
	private function _invalid_username_or_incorrect_password() {
		return null;		// To be processed by the function `wp_authenticate`.
	}

	/**
	 * Send an email notifying the login of the administrator.
	 * 
	 * @since 2.2.0
	 * 
	 * @param WP_User $user WP_User instance.
	 */
	private function _notify_admin_login( $user = null ) {
		if ( is_null( $user ) && function_exists( 'wp_get_current_user' ) )
			$user = wp_get_current_user();
		if ( isset( $user->user_email ) && isset( $user->user_login ) ) {
			$to = trim( $user->user_email );
			$blogname = wp_specialchars_decode( get_option( 'blogname' ), ENT_QUOTES );
			$login = wp_specialchars_decode( $user->user_login, ENT_QUOTES );
			$user_agent = isset( $_SERVER['HTTP_USER_AGENT'] )? wp_specialchars_decode( $_SERVER['HTTP_USER_AGENT'], ENT_QUOTES ): 'None';
			$message = __( "Logged in information:" )."\r\n\r\n";
			$message .= sprintf( __( 'Site URL: %s' ), get_option( 'siteurl' ) ) . "\r\n";
			$message .= sprintf( __( 'User name: %s' ), $user->user_login ) . "\r\n";
			$message .= sprintf( __( 'Date time: %s' ), date_i18n( 'Y-m-d H:i:s' ) ) . "\r\n";
			$message .= sprintf( __( 'IP address: %s' ), $this->remote_addr ) . "\r\n";
			$message .= sprintf( __( 'User agent: %s' ), $user_agent ) . "\r\n\r\n";
			$message .= __( "If you are not logged in, promptly take appropriate measures." )."\r\n";
			wp_mail( $to, sprintf( __( '[%s] %s logged in.' ), $blogname, $login ), $message );
		}
	}

	/**
	 * Display a button to download the log file.
	 * 
	 * @since 2.3.0
	 * 
	 * @access private.
	 * 
	 * @param string $type Log data type( 'invalid', 'login', 'pingback' ).
	 */
	private function _download_log_form( $type ) {
?>
&nbsp;<form method="post" action="<?php echo admin_url( 'admin-ajax.php' ); ?>?action=login_rebuilder_download_log" style="display: inline-block;">
<?php wp_nonce_field( self::LOGIN_REBUILDER_AJAX_NONCE_NAME.$this->_nonce_suffix() ); ?>
<input type="hidden" name="type" value="<?php echo esc_attr( $type ); ?>" />
<button type="submit" class=" button-link"><span class="dashicons dashicons-download"></span></button>
</form>
<?php
	}

	/**
	 * Download log file.
	 * 
	 * @since 2.3.0
	 * 
	 * @access public.
	 */
	public function download_log() {
		check_admin_referer( self::LOGIN_REBUILDER_AJAX_NONCE_NAME.$this->_nonce_suffix() );

		if ( current_user_can( 'manage_options' ) && isset( $_POST['type'] ) &&
			in_array( $_POST['type'], array( 'invalid', 'login', 'pingback' ) ) ) {

			$this->logging_widget = $this->_get_logging();
			$out = '';
			if ( isset( $this->logging_widget[$_POST['type']] ) && is_array( $this->logging_widget[$_POST['type']] ) ) {
				$gmt_offset = get_option( 'gmt_offset' );

				ob_start();
				$fp = fopen( 'php://output', 'w' );
				foreach ( $this->logging_widget[$_POST['type']] as $i=>$log ) {
					if ( 0 === $i && $this->properties['contains_heading_line'] ) {
						fputcsv( $fp, $this->_log_heading_line( $log, $_POST['type'] ) );
					}
					$log['time'] = date_i18n( 'Y-m-d H:i:s', $log['time']+$gmt_offset*3600 );
					fputcsv( $fp, $log );
				}
				fclose( $fp );
				$out = "\xef\xbb\xbf".ob_get_clean();	// add BOM
			}
			if ( !empty( $out ) ) {
				$filename = $this->_logfile_name( $_POST['type'] );
				header( 'Content-Type: text/csv' );
				header( 'Content-Disposition: attachment; filename='.$filename );
				header( 'Expires: 0' );
				header( 'Cache-Control: must-revalidate, post-check=0, pre-check=0' );
				header( 'Pragma: public' );
				header( 'Content-Length:'.strlen( $out ) );
				echo $out;
			}
		}
		die;
	}

	/**
	 * Validate the limit value.
	 * 
	 * @since 2.3.0
	 * 
	 * @access private.
	 * 
	 * @param int $num
	 * @return int
	 */
	private function _validate_logging_limit( $num ) {
		if ( self::LOGIN_REBUILDER_LOGGING_LIMIT_MIN > $num )
			return self::LOGIN_REBUILDER_LOGGING_LIMIT_MIN;
		else if ( self::LOGIN_REBUILDER_LOGGING_LIMIT_MAX < $num )
			return self::LOGIN_REBUILDER_LOGGING_LIMIT_MAX;
		return $num;
	}

	/**
	 * Retrieve a heading line for log file.
	 * 
	 * @since 2.3.0
	 * 
	 * @access private.
	 * 
	 * @param array $log
	 * @param string $type
	 * @return array
	 */
	private function _log_heading_line( $log, $type ) {
		$keys = array_keys( $log );
		foreach ( $keys as $i=>$name ) {
			switch ( $name ) {
				case 'time':
					$keys[$i] = 'date and time';
					break;
				case 'ip':
					$keys[$i] = 'IP address';
					break;
				case 'pw':
					$keys[$i] = 'password';
					break;
				case 'id':
					if ( 'invalid' === $type )
						$keys[$i] = 'login id';
					else if ( 'login' === $type )
						$keys[$i] = 'user id';
					break;
			}
		}
		return $keys;
	}

	/**
	 * Retrieve a filename of log file.
	 * 
	 * @since 2.3.0
	 * 
	 * @access private.
	 * 
	 * @param string $type
	 * @return string
	 */
	private function _logfile_name( $type ) {
		$hostname = isset( $_SERVER['HTTP_HOST'] )? sanitize_key( $_SERVER['HTTP_HOST'] ): ''; 
		if ( !empty( $hostname ) ) $hostname .= '-';
		return $hostname.$type.'-log-'.date( 'Ymd_His' ).'.csv';
	}

	/**
	 * Author pages should not be redirected.
	 * 
	 * @since 2.4.0
	 * 
	 * @access public.
	 * 
	 * @param string $redirect_url  The redirect URL.
	 * @param string $requested_url The requested URL.
	 * @return string
	 */
	public function author_page_canonical( $redirect_url, $requested_url ) {
		if ( is_author() ) {
			$author = get_userdata( get_query_var( 'author' ) );
			if ( false !== $author && $redirect_url == get_author_posts_url( $author->ID, $author->user_nicename ) )
				$redirect_url = null;
		}
		return $redirect_url;
	}

	/**
	 * Change the response of the author page to 404.
	 * 
	 * @since 2.4.0
	 * 
	 * @access public.
	 */
	public function author_page_404() {
		if ( is_author() ) {
			global $wp_query;
			$wp_query->is_author = false;
			$wp_query->is_404 = true;
		}
	}

	/**
	 * Set site information in author_name and author_url.
	 * 
	 * @since 2.4.1
	 * 
	 * @access public
	 * 
	 * @param array   $data   The response data.
	 * @param WP_Post $post   The post object.
	 * @param int     $width  The requested width.
	 * @param int     $height The calculated height.
	 */
	public function oembed_hide_author_data( $data, $post, $width, $height ) {
		if ( isset( $data['author_name'] ) ) {
			$data['author_name'] = get_bloginfo( 'name' );
		}
		if ( isset( $data['author_url'] ) ) {
			$data['author_url'] = get_home_url();
		}
		return $data;
	}

	/**
	 * Disable oembed of REST API.
	 * 
	 * @since 2.4.1
	 * 
	 * @access public
	 * 
	 * @param mixed           $response Response to replace the requested version with.
	 * @param WP_REST_Server  $server   Server instance.
	 * @param WP_REST_Request $request  Request used to generate the response.
	 */
	public function disable_oembed_request( $response, $server, $request ) {
		if ( 0 === strpos( $request->get_route(), '/oembed/' ) ) {
			return new WP_Error( 'oembed request has disabled', __( 'This REST API has been disabled.' ) );
		}
		return $response;
	}

	/**
	 * Set the original confirmation url in advance.
	 * 
	 * @since 2.4.2
	 * 
	 * @access public
	 * 
	 * @see wp_send_user_request()
	 * 
	 * @param string $email_text Text in the email.
	 * @param array  $email_data.
	 */
	public function set_original_confirmaction_url( $email_text, $email_data ) {
		$confirm_url = str_replace( site_url( 'wp-login.php' ), $this->_original_site_url( 'wp-login.php' ), $email_data['confirm_url'] );
		return str_replace( '###CONFIRM_URL###', esc_url_raw( $confirm_url ), $email_text );
	}

	/**
	 * Get the original site url.
	 * 
	 * @since 2.4.2
	 * 
	 * @access private
	 * 
	 * @param string $path
	 * @return string
	 */
	private function _original_site_url( $path ) {
		$keep_status = $this->properties['status'];
		$this->properties['status'] = self::LOGIN_REBUILDER_STATUS_IN_PREPARATION;
		$site_url = site_url( $path );
		$this->properties['status'] = $keep_status;
		return $site_url;
	}

	/**
	 * Check status of lock file.
	 * 
	 * @since 2.5.0
	 * 
	 * @access private
	 * 
	 * @see self::role_authenticate()
	 * 
	 * @param bool $use
	 * @param string $path
	 * @return bool
	 */
	private function _lock_file_valid( $use = null, $path = null ) {
		if ( is_null( $use ) ) {
			$use = $this->properties['use_lock_file'];
		}
		if ( is_null( $path ) ) {
			$path = $this->properties['lock_file_path'];
		}
		return ( $use && ! empty( $path ) && @ file_exists( $path ) );
	}

	/**
	 * Get text indicating state of lock file.
	 * 
	 * @since 2.5.0
	 * 
	 * @access private
	 * 
	 * @see self::lock_exists()
	 * @see self::_view_log_of_login()
	 * 
	 * @param bool $use
	 * @param bool $exists
	 * @return string
	 */
	private function _lock_file_status( $use, $exists ) {
		if ( $exists ) {
			if ( $use ) {
				$status = __( 'File exists, ', LOGIN_REBUILDER_DOMAIN ) . __( 'No login allowed', LOGIN_REBUILDER_DOMAIN );
			} else {
				$status = __( 'File exists, ', LOGIN_REBUILDER_DOMAIN ) . __( 'Login possible', LOGIN_REBUILDER_DOMAIN );
			}
		} else {
			$status = __( 'File not found, ', LOGIN_REBUILDER_DOMAIN ) . __( 'Login possible', LOGIN_REBUILDER_DOMAIN );
		}
		return $status;
	}

	/**
	 * Show locked status on pop-up re-login form
	 * 
	 * @since 2.5.0
	 * 
	 * @access public
	 * 
	 * @see self::__construct()
	 */
	public function login_locked_status( $messages ) {
		if ( isset( $GLOBALS['interim_login'] ) &&
			$GLOBALS['interim_login'] &&
			$this->_in_url( $this->request_uri, $this->properties['page'] ) &&
			$this->_lock_file_valid( $this->properties['use_lock_file'], $this->properties['lock_file_path'] ) ) {
			$messages .= '<span style="color: red;">' . esc_html__( 'Authentication is locked, please login after unlocking.', LOGIN_REBUILDER_DOMAIN ). '</span><br />';
		}
		return $messages;
	}

	/**
	 * Adjust the current locale required for the alternative login page.
	 * 
	 * @since 2.5.0
	 * 
	 * @access public
	 * 
	 * @see self::__construct()
	 * 
	 * @param string $locale
	 * @return string
	 */
	public function determined_locale( $locale ) {
		if ( ! empty( $_GET['wp_lang'] ) && (
			( ! empty( $this->properties['page'] ) && basename( $this->properties['page'] ) === $GLOBALS['pagenow'] ) ||
			( ! empty( $this->properties['page_subscriber'] ) && basename( $this->properties['page_subscriber'] ) === $GLOBALS['pagenow'] )
			) ) {
			$locale = sanitize_text_field( $_GET['wp_lang'] );
		}
		return $locale;
	}
}