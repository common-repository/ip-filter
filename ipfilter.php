<?php
/*
Plugin Name: IP Filter
Plugin URI: http://www.gabsoftware.com/products/scripts/ip-filter/
Description: Grants or denies access to a list of IP addresses.
Author: Hautclocq Gabriel
Author URI: http://www.gabsoftware.com/
Version: 1.0.3
Tags: ip, filter, ban, block, grant, allow, deny, stop, plugin, security, spam, whitelist, blacklist
License: ISC
*/

// Security check. We do not want to be able to access our plugin directly.
if( !defined( 'WP_PLUGIN_DIR') )
{
	die("There is nothing to see here.");
}

/*
 * global variables for our plugin
 */

//version
$ipfilter_version_maj = 1;
$ipfilter_version_min = 0;
$ipfilter_version_rev = 3;
$ipfilter_version = "{$ipfilter_version_maj}.{$ipfilter_version_min}.{$ipfilter_version_rev}";

// Absolute path of the plugin from the server view
// (eg: "/home/gabriel/public_html/blog/wp-content/plugins/ipfilter")
$ipfilter_plugin_dir = WP_PLUGIN_DIR . '/' . plugin_basename( dirname( __FILE__) );

// Public URL of your plugin
// (eg: "/blog/wp-content/plugins/ipfilter")
$ipfilter_plugin_url = WP_PLUGIN_URL . '/' . plugin_basename( dirname( __FILE__) );

/* Constants */
define( 'IPFILTER_TEXTDOMAIN', 'ipfilter' );
define( 'IPFILTER_DEFAULT_FILTER', 'deny' );
define( 'IPFILTER_DEFAULT_LOG_BLOCKED_IPS', false );
define( 'IPFILTER_DEFAULT_BYPASS_URL', 'ipfilter_bypass');
//define( 'IPFILTER_IPv4_REGEX', '#(\d{1,3}|\*)\.(\d{1,3}|\*)\.(\d{1,3}|\*)\.(\d{1,3}|\*)#' );
//define( 'IPFILTER_IPv4_REGEX', '#([0-9\*]{1,3}\.?){1,4}#' );
define( 'IPFILTER_IPv4_REGEX', '#((\d{1,3}|\*)(\.(\d{1,3}|\*)){1,3}|\*)#' );
define( 'IPFILTER_IPv6_REGEX', '#\s*((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|(([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}|((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(:(((:[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:)))(%.+)?\s*#' );

$ipfilter_default_deny_message = '';

/*
 * Beginning of our plugin class
 */
class IPFilter
{
	//This should be either "grant" or "deny".
	private $filter_type = 'deny';

	//This is our filtered IP address list
	private $filtered_ips = array();
	private $filtered_ips_raw = '';

	//The message shown to users whom access has been denied
	private $deny_message;

	//Whether we should log the blocked IP addresses or not
	private $log_blocked_ips = false;

	private $bypass_url = 'ipfilter_bypass';

	/*
	 * Our plugin constructor
	 */
	function __construct()
	{
		// Place your add_actions and add_filters here
		add_action( 'init', array( &$this, 'init_callback' ), 0 );
	} // end of constructor

	/*
	 * Place your plugin initialization code here
	 * For example, load your plugin translations here, not before.
	 */
	public function init_callback()
	{
		global $ipfilter_plugin_dir;
		global $ipfilter_default_deny_message;

		// Load the plugin localization (.mo files) located
		// in the plugin "lang" subdirectory
		if( function_exists( 'load_plugin_textdomain' ) )
		{
			load_plugin_textdomain(
				IPFILTER_TEXTDOMAIN,
				false,
				$ipfilter_plugin_dir . '/lang'
			);
		}

		$this->should_install();

		$ipfilter_default_deny_message = __( 'Access denied', IPFILTER_TEXTDOMAIN );

		//load the plugin options
		$this->load_options();

		//grant or deny access to the current visitor IP address
		$this->grant_or_deny_access();

		//Do the administrative stuff only if we are in the administration area
		if( is_admin() )
		{
			if( current_user_can( 'manage_options' ) )
			{
				//Add admin actions
				add_action( 'admin_init', array( &$this, 'admin_init_callback' ) );
				add_action( 'admin_menu', array( &$this, 'add_page_admin_callback' ) );
			}
		}
	} // end of function

	/*
	 * Gets all or part of the version of IP Filter
	 */
	public function get_version( $what = 'all' )
	{
		global $ipfilter_version;

		$version = get_option( 'ipfilter_version' );

		if( empty( $version ) )
		{
			$version = '1.0.1'; //because this option exist since version 1.0.1
		}

		switch( $what )
		{
			case 'major':
				$version_array = explode( '.', $version );
				return $version_array[0];
				break;

			case 'minor':
				$version_array = explode( '.', $version );
				return $version_array[1];
				break;

			case 'revision':
				$version_array = explode( '.', $version );
				return $version_array[2];
				break;

			case 'all':
			default:
				return $version;
		}
	}

	/*
	 * Checks if IP Filter should be installed or upgraded
	 */
	public function should_install()
	{
		global $ipfilter_version_maj;
		global $ipfilter_version_min;
		global $ipfilter_version_rev;

		$majver = $this->get_version( 'major' );
		$minver = $this->get_version( 'minor' );
		$revver = $this->get_version( 'revision' );


		if( $majver != $ipfilter_version_maj || $minver != $ipfilter_version_min || $revver != $ipfilter_version_rev )
		{
			$this->install( $ipfilter_version_maj, $ipfilter_version_min, $ipfilter_version_rev );
		}
	}

	/*
	 * Installation and upgrade routine of the plugin
	 */
	public function install( $vermajor, $verminor, $verrevision )
	{
		global $ipfilter_version;


		$majver = $this->get_version( 'major' );
		$minver = $this->get_version( 'minor' );
		$revver = $this->get_version( 'revision' );

		/* begin installation routine */
		//nothing yet
		/* end installation routine */

		/* begin upgrade routine */
		if( $majver == 1 )
		{
			if( $minver == 0 )
			{
				if( $revver < 2 )
				{
					//add the version
					add_option( 'ipfilter_version', $ipfilter_version );
				}
				if( $revver < 3 )
				{
					//add the version
					$this->set_option( 'ipfilter_bypass_url', IPFILTER_DEFAULT_BYPASS_URL );
				}
			}
		}
		update_option( 'ipfilter_version', $ipfilter_version );
		/* end upgrade routine */
	} //function

	// Returns the value of the specified option
	public function get_option( $name = NULL )
	{
		//retrieve the current options array
		$options = get_option( 'ipfilter_options' );

		//add the options array if it does not exist
		if( $options === FALSE )
		{
			add_option( 'ipfilter_options', array() );
		}

		//return the options array if name is null,
		// or the specified option in the options array,
		// or FALSE otherwise
		if( is_null( $name ) )
		{
			return get_option( 'ipfilter_options' );
		}
		elseif( isset( $options[$name] ) )
		{
			return $options[$name];
		}
		else
		{
			return FALSE;
		}
	}

	// Sets the value of the specified option
	public function set_option( $name, $value )
	{
		$options = $this->get_option( NULL );
		if( $options === FALSE )
		{
			$options = Array();
		}
		$options[$name] = $value;

		return update_option( 'ipfilter_options', $options );
	}


	//retrieve options from the Worpress options table
	public function load_options()
	{
		global $ipfilter_default_deny_message;

		//load the ipfilter_filter_type option
		if( ( $tmp = $this->get_option( 'filter_type' ) ) !== FALSE )
		{
			if( $tmp != 'deny' && $tmp != 'grant' )
			{
				$this->set_option( 'filter_type', IPFILTER_DEFAULT_FILTER );
				$tmp = IPFILTER_DEFAULT_FILTER;
			}
		}
		else
		{
			$this->set_option( 'filter_type', IPFILTER_DEFAULT_FILTER );
			$tmp = IPFILTER_DEFAULT_FILTER;
		}
		$this->filter_type = $tmp;

		//load the ipfilter_filtered_ips option
		if( ( $tmp = $this->get_option( 'filtered_ips' ) ) === FALSE )
		{
			$this->set_option( 'filtered_ips', '' );
			$tmp = '';
		}
		$this->filtered_ips_raw = $tmp;
		$this->filtered_ips = $this->load_ips();


		//load the ipfilter_deny_message option
		if( ( $tmp = $this->get_option( 'deny_message' ) ) === FALSE )
		{
			$this->set_option( 'deny_message', $ipfilter_default_deny_message );
			$tmp = $ipfilter_default_deny_message;
		}
		$this->deny_message = $tmp;

		//load the ipfilter_log_blocked_ips option
		if( ( $tmp = $this->get_option( 'log_blocked_ips' ) ) === FALSE )
		{
			$this->set_option( 'log_blocked_ips', IPFILTER_DEFAULT_LOG_BLOCKED_IPS );
			$tmp = IPFILTER_DEFAULT_LOG_BLOCKED_IPS;
		}
		$this->log_blocked_ips = $tmp;

		//load the ipfilter_bypass_url option
		if( ( $tmp = $this->get_option( 'bypass_url' ) ) === FALSE )
		{
			$this->set_option( 'bypass_url', IPFILTER_DEFAULT_BYPASS_URL );
			$tmp = IPFILTER_DEFAULT_BYPASS_URL;
		}
		$this->bypass_url = $tmp;
	}

	public function load_ips()
	{
		$res = array();
		$ipv4 = array();
		$ipv6 = array();
		$nb = preg_match_all( IPFILTER_IPv4_REGEX, $this->filtered_ips_raw, $ipv4 );
		if( $nb !== FALSE && $nb > 0 )
		{
			$res = array_merge( $res, $ipv4[0] );
		}
		$nb = preg_match_all( IPFILTER_IPv6_REGEX, $this->filtered_ips_raw, $ipv6 );
		if( $nb !== FALSE && $nb > 0 )
		{
			$res = array_merge( $res, $ipv6[0] );
		}

		return $res;
	}

	//returns TRUE if string is matched by pattern after pattern has been transformed to a regular expression
	private function fnmatch( $pattern, $string )
	{
		$regex = '/^' . strtr( addcslashes( $pattern, '.+^$(){}=!<>|' ), array( '*' => '.*', '?' => '.?' ) ) . '$/i';
		//var_dump( $regex );
		//var_dump( $string);
		return @preg_match( $regex, $string );
	}


	//This function is similar to in_array but allows wildcards in the array to be searched
	function wildcard_in_array($needle, $haystack)
	{
		foreach( $haystack as $value )
		{
			$test = $this->fnmatch( $value, $needle );
			if( $test !== FALSE && $test > 0 )
			{
				return TRUE;
			}
		}
		return FALSE;
	}

	//Grant or deny access to the current visitor
	public function grant_or_deny_access()
	{
		global $ipfilter_plugin_dir;

		//exclude administrators
		if( current_user_can( 'manage_options' ) )
		{
			return;
		}

		//do not block if we access the administration area
		if( is_admin() )
		{
			return;
		}

		//A way for admins to get access back to the blog if they managed to block themselves
		if( ! empty( $this->bypass_url ) && isset( $_GET[ $this->bypass_url ] ) )
		{
			return;
		}

		$visitor_ips = $this->get_visitor_ips();

		//TRUE = deny, FALSE = grant
		$boolean = ( $this->filter_type == 'deny' );

		foreach( $visitor_ips as $visitor_ip )
		{
			//if the IP address IS in the list, we deny access
			if( $this->wildcard_in_array( $visitor_ip, $this->filtered_ips ) == $boolean )
			{
				if( $this->log_blocked_ips == true )
				{
					//We record the blocked IP into the log
					$logline = "Blocked: {$visitor_ip}, on " . date( 'Y-m-d H:i:s' ) . ", using '{$_SERVER['HTTP_USER_AGENT']}', trying to access '{$_SERVER['REQUEST_URI']}'\n";
					file_put_contents( $ipfilter_plugin_dir . '/logs/log.txt', $logline, FILE_APPEND | LOCK_EX );
				}

				//deny access
				header( 'Status: 403 Forbidden' );
				header( 'HTTP/1.1 403 Forbidden' );
				wp_die( $this->deny_message );
			}
		}
	}



	/**
	 * Get visitor IP addresses
	 *
	 * @uses HTTP_CLIENT_IP - Shared Internet IP
	 * @uses HTTP_X_FORWARDED_FOR - Proxy IP
	 * @uses REMOTE_ADDR - Public IP
	 * @return (array) Array containing possible IPs
	 */
	function get_visitor_ips()
	{
		$ips = Array();

		$ips[] = $_SERVER['REMOTE_ADDR'];

		if( !empty( $_SERVER['HTTP_CLIENT_IP'] ) )
		{
			$ips[] = $_SERVER['HTTP_CLIENT_IP'];
		}

		if( !empty( $_SERVER['HTTP_X_FORWARDED_FOR'] ) )
		{
			$ips[] =$_SERVER['HTTP_X_FORWARDED_FOR'];
		}

		return $ips;
	} // function



	/*
	 * Registers our admin page, admin menu and admin CSS/Javascript
	 */
	public function add_page_admin_callback()
	{
		//We add our options page into the Settings section
		$ipfilter_options_page_handle = add_submenu_page(
			'options-general.php',
			__('IP Filter options', IPFILTER_TEXTDOMAIN),
			__('IP Filter', IPFILTER_TEXTDOMAIN),
			'manage_options',
			'ipfilter_options_page_id',
			array( &$this, 'options_page_callback' )
		);

		//specify that we want to alter the links in the plugins page
		add_filter( 'plugin_action_links_' . plugin_basename(__FILE__), array( &$this, 'filter_plugin_actions_callback' ), 10, 2 );
	}


	//add a Configure link in the plugins page
	public function filter_plugin_actions_callback($links, $file)
	{
		$settings_link = '<a href="options-general.php?page=ipfilter_options_page_id">' . __('Configure', IPFILTER_TEXTDOMAIN) . '</a>';
		array_unshift( $links, $settings_link ); // add the configure link before other links
		return $links;
	}


	/*
	 * Content of the options page
	 */
	public function options_page_callback()
	{
		global $ipfilter_plugin_dir;

		//Insufficient capabilities? Go away.
		if ( ! current_user_can( 'manage_options' ) )
		{
			die ( __( "You don't have sufficient privileges to display this page", IPFILTER_TEXTDOMAIN ) );
		}
		?>

		<div class="wrap">
			<div class="icon32" id="icon-options-general"></div>

			<h2><?php echo __('IP Filter configuration', IPFILTER_TEXTDOMAIN); ?></h2>

			<form method="post" action="options.php">

				<?php

				settings_fields( 'ipfilter_options_group' );
				do_settings_sections( 'ipfilter_options_page_id' );

				?>

				<p class="submit">
					<input type="submit" class="button-primary" value="<?php _e( 'Save Changes', IPFILTER_TEXTDOMAIN ); ?>" />
				</p>
			</form>

			<h2><?php echo __('Blocked IP addresses in log file', IPFILTER_TEXTDOMAIN); ?></h2>

			<textarea readonly='readonly'
			          cols='140'
			          rows='15'><?php
				if( file_exists( $ipfilter_plugin_dir . '/logs/log.txt' ) )
				{
					echo strip_tags( htmlspecialchars( file_get_contents( $ipfilter_plugin_dir . '/logs/log.txt' ) ) );
				}
			?></textarea>

		</div>

		<?php
	}


	/*
	 * Executed when Wordpress initialize the administration section.
	 * Inside we register our admin options.
	 */
	public function admin_init_callback()
	{
		//register option group
		register_setting( 'ipfilter_options_group', 'ipfilter_options', array( &$this, 'options_validate_callback' ) );

		//add sections
		add_settings_section('ipfilter_options_section_general', __('General', IPFILTER_TEXTDOMAIN), array( &$this, 'options_display_section_general_callback' ), 'ipfilter_options_page_id' );

		//section Appearance
		add_settings_field('ipfilter_setting_filtertype'    , __( 'Filter type (deny or grant):'                                   , IPFILTER_TEXTDOMAIN ), array( &$this, 'options_display_filtertype_callback'    ), 'ipfilter_options_page_id', 'ipfilter_options_section_general' );
		add_settings_field('ipfilter_setting_filteredips'   , __( 'List of IP addresses to filter:
			<ul style="list-style-type: circle">
				<li>Free format</li>
				<li>Comments are allowed</li>
				<li>IPv4 and IPv6 addresses allowed</li>
				<li>Wildcard character "*" is accepted for IPv4 but it must represent a complete field.
					<ul style="list-style-type: square">
						<li>Correct: 10.*.*.*</li>
						<li>Correct: 10.*</li>
						<li>Correct: *.20</li>
						<li><strong>Incorrect: 10.2*</strong></li>
					</ul>
				</li>
			</ul>', IPFILTER_TEXTDOMAIN ), array( &$this, 'options_display_filteredips_callback'   ), 'ipfilter_options_page_id', 'ipfilter_options_section_general' );
		add_settings_field('ipfilter_setting_denymessage'   , __( 'Message shown to filtered visitors (HTML accepted):'            , IPFILTER_TEXTDOMAIN ), array( &$this, 'options_display_denymessage_callback'   ), 'ipfilter_options_page_id', 'ipfilter_options_section_general' );
		add_settings_field('ipfilter_setting_bypass_url'    , __( 'URL parameter to bypass the filter (empty string to disable):'  , IPFILTER_TEXTDOMAIN ), array( &$this, 'options_display_bypass_url_callback'    ), 'ipfilter_options_page_id', 'ipfilter_options_section_general' );
		add_settings_field('ipfilter_setting_logblockedips' , __( 'Check if you want to log blocked IP addresses:'                 , IPFILTER_TEXTDOMAIN ), array( &$this, 'options_display_logblockedips_callback' ), 'ipfilter_options_page_id', 'ipfilter_options_section_general' );
		add_settings_field('ipfilter_setting_purge_logfile' , __( 'Check if you want to purge the log file:'                       , IPFILTER_TEXTDOMAIN ), array( &$this, 'options_display_purgelogfile_callback'  ), 'ipfilter_options_page_id', 'ipfilter_options_section_general' );
	}

	//display the General section
	public function options_display_section_general_callback()
	{
		echo '<p>' . __( 'General options for IP Filter', IPFILTER_TEXTDOMAIN ) . '</p>';
	}

	//display the filter type option field
	public function options_display_filtertype_callback()
	{
		$options = $this->get_option( NULL );
		//set a default value if no value is set
		if( $options === FALSE || empty( $options['filter_type'] ) )
		{
			$options['filter_type'] = IPFILTER_DEFAULT_FILTER;
		}
		?>
		<input id='ipfilter_setting_filtertype1'
		       name='ipfilter_options[filter_type]'
		       type='radio'
		       value='deny'<?php  echo ( $options['filter_type'] == 'deny'  ? ' checked="checked"' : '' ); ?> />
		<label for='ipfilter_setting_filtertype1'><?php _e( 'Deny access to IP addresses in the list (tip: do not add your own IP address...)', IPFILTER_TEXTDOMAIN ) ?></label>
		<br />

		<input id='ipfilter_setting_filtertype2'
		       name='ipfilter_options[filter_type]'
		       type='radio'
		       value='grant'<?php echo ( $options['filter_type'] == 'grant' ? ' checked="checked"' : '' ); ?> />
		<label for='ipfilter_setting_filtertype2'><?php _e( 'Grant access to IP addresses in the list only (be sure to add your IP address!)', IPFILTER_TEXTDOMAIN ) ?></label>
		<?php
	}

	//display the filtered ips option field
	public function options_display_filteredips_callback()
	{
		$options = $this->get_option( NULL );
		//set a default value if no value is set
		if( $options === FALSE || empty( $options['filtered_ips'] ) )
		{
			$options['filtered_ips'] = '';
		}
		?>
		<textarea id='ipfilter_setting_filteredips'
		          name='ipfilter_options[filtered_ips]'
		          cols='40'
		          rows='12'
		          style='display: inline-block'><?php
			echo $options['filtered_ips'];
		?></textarea>
		<textarea cols='25'
		          rows='12'
		          readonly='readonly'
		          style='display: inline-block'><?php
			_e( 'Extracted:', IPFILTER_TEXTDOMAIN );
			foreach( $this->filtered_ips as $ip )
			{
				echo "\n" . $ip;
			}
		?></textarea>
		<?php
	}

	//display the deny message option field
	public function options_display_denymessage_callback()
	{
		global $ipfilter_default_deny_message;

		$options = $this->get_option( NULL );
		//set a default value if no value is set
		if( $options === FALSE || empty( $options['deny_message'] ) )
		{
			$options['deny_message'] = $ipfilter_default_deny_message;
		}
		?>

		<textarea id='ipfilter_setting_denymessage'
		          name='ipfilter_options[deny_message]'
		          cols='70'
		          rows='5'><?php
			echo esc_textarea( $options['deny_message'] );
		?></textarea>

		<?php
	}

	//display the bypass_url field
	public function options_display_bypass_url_callback()
	{
		$options = $this->get_option( NULL );
		//set a default value if no value is set
		$placeholder = '';
		if( $options === FALSE || empty( $options['bypass_url'] ) )
		{
			$options['bypass_url'] = '';
			$placeholder = __( '(currently disabled)', IPFILTER_TEXTDOMAIN );
		}
		?>

		<input type='text'
		       id='ipfilter_setting_bypass_url'
		       name='ipfilter_options[bypass_url]'
		       width='60'
		       placeholder='<?php echo $placeholder; ?>'
		       value='<?php echo esc_textarea( $options['bypass_url'] ); ?>' />

		<?php
	}

	//display the log blocked ips option field
	public function options_display_logblockedips_callback()
	{
		$options = $this->get_option( NULL );
		//set a default value if no value is set
		if( $options === FALSE || empty( $options['log_blocked_ips'] ) )
		{
			$options['log_blocked_ips'] = false;
		}
		?>

		<input
			id='ipfilter_setting_logblockedips'
			name='ipfilter_options[log_blocked_ips]'
			type='checkbox'
			value='logblockedips'<?php echo ( $options['log_blocked_ips'] == 'logblockedips' ? ' checked="checked"' : '' ); ?> />

		<?php
	}

	//display the purge log file option field
	public function options_display_purgelogfile_callback()
	{
		?>

		<input
			id='ipfilter_setting_purgelogfile'
			name='ipfilter_options[purge_log_file]'
			type='checkbox'
			value='purgelogfile' />

		<?php
	}

	//validate the filter options
	public function options_validate_callback( $input )
	{
		//load the current options
		$newinput = $this->get_option( NULL );

		//validate the filter type
		if( isset( $input['filter_type'] ) )
		{
			if( $input['filter_type'] != 'deny' && $input['filter_type'] != 'grant' )
			{
				$newinput['filter_type'] = IPFILTER_DEFAULT_FILTER;
			}
			else
			{
				$newinput['filter_type'] = $input['filter_type'];
			}
		}

		//validate the filtered ips list
		if( isset( $input['filtered_ips'] ) )
		{
			$newinput['filtered_ips'] = htmlspecialchars( strip_tags( $input['filtered_ips'] ) );
		}

		//validate the deny message
		if( isset( $input['deny_message'] ) )
		{
			$newinput['deny_message'] = $input['deny_message'];
		}

		//validate the bypass_url option
		if( isset( $input['bypass_url'] ) )
		{
			$newinput['bypass_url'] = strip_tags( $input['bypass_url'] );
		}

		//validate the log blocked ips switch
		if( isset( $input['log_blocked_ips'] ) )
		{
			$newinput['log_blocked_ips'] = true;
		}
		else
		{
			$newinput['log_blocked_ips'] = false;
		}

		if( isset( $input['purge_log_file'] ) )
		{
			//purge the log file
			global $ipfilter_plugin_dir;
			file_put_contents( $ipfilter_plugin_dir . '/logs/log.txt', '', LOCK_EX );
		}

		return $newinput;
	}
}
// End of class


/*
 * Instanciate a new instance of IPFilter
 */
new IPFilter();