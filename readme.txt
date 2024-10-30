=== IP Filter ===
Contributors: GabSoftware
Donate link: http://www.gabsoftware.com/donate/
Tags: ip, filter, ban, block, grant, allow, deny, stop, plugin, security, spam, whitelist, blacklist
Requires at least: 3.0.0
Tested up to: 3.3.1
Stable tag: 1.0.3

Grants or denies access to a list of IP addresses

== Description ==

<p>
Grants or denies access to a list of IP addresses.
</p>

<p>
Unauthorized IP addresses will get a 403 Forbidden HTTP header.
</p>

<p>
The error message is customizable and can contain HTML.
</p>

<p>
Blocked IP addresses can be logged.
</p>

<p>
IP addresses to be filtered can be typed in a text zone. Here is a list of what you can put in this text zone:
</p>
<ul style="list-style-type: circle">
	<li>Free format, you are not limited to put one IP address per line</li>
	<li>Comments are allowed and will be ignored by IP Filter, but they should not contain IP addresses and the "*" character</li>
	<li>IPv4 and IPv6 addresses are allowed</li>
	<li>Wildcard character "*" is accepted for IPv4 but it must represent a complete field. IP addresses without wildcard can't be truncated. Examples:
		<ul style="list-style-type: square">
			<li>Correct: 10.20.30.40</li>
			<li>Correct: 10.20.*.40</li>
			<li>Correct: 10.*.*.*</li>
			<li>Correct: 10.*</li>
			<li>Correct: *.20</li>
			<li>Correct: *</li>
			<li><strong>Incorrect: 10.2*</strong></li>
			<li><strong>Incorrect: 10.20</strong></li>
			<li><strong>Incorrect: 10.2*.30.40</strong></li>
		</ul>
	</li>
</ul>


<p>
Be careful about the following points:
</p>

<ol>
<li>If you choose the "deny" filter type and you add your IP to the deny list, you will loose access to your website</li>
<li>If you choose the "grant" filter type and you do not add your IP to the list, you will loose access to your website</li>
<li>If you add the "*" filter, nobody will be able to access to your website</li>
</ol>

<strong>This plugin requires PHP 5 and Wordpress 3.x</strong>

== Installation ==

<p>
Just extract the plugin directory into your wp-content/plugins directory.
</p>

== Frequently Asked Questions ==

= I blocked myself! What can I do? =
* In case you did the mistake to block yourself from your blog, you still can get access your administration panel by going to the "/wp-admin/" URL
* Additionnally, the filter can be bypassed by adding the "ipfilter_bypass" parameter to the URL (eg: http://www.myblog.com/?ipfilter_bypass)

= Can I put some HTML into the custom message? =

Yes. But why bother if you just want to block those annoying visitors? You'd better save bandwidth.

= Can I add IP ranges instead of complete IP addresses? =

You can use the wildcard character "*". It is planned to add a mode that use regular expressions, but without any ETA.

= Why isn't IP Filter translated in my language? =

Most probably because nobody submitted a translation for your language yet. But you can help.
Read our guide for plugins translators at http://www.gabsoftware.com/tips/a-guide-for-wordpress-plugins-translators-gettext-poedit-locale/

== Screenshots ==

1. IP Filter settings in Wordpress administration area

== Changelog ==

= 1.0.3 =
* The message shown to filtered visitors can now include HTML code
* The message shown to filtered visitors can now contain HTML special characters such as quotes, double quotes, etc.
* The bypass URL parameter can be customized and disabled as well
* Now use wp_die instead of die

= 1.0.2 =
* Added possibility to use the wildcard character "*"
* It is now possible to purge the log file in the settings page
* Code cleaning and simplification
* Added a zone that displays the IP addresses extracted from your input

= 1.0.1 =
* Added log options

= 1.0.0 =
* Initial release

== Upgrade Notice ==

= 1.0.0 =
* Thank you for using IP Filter! Click on the "Configure" link in the "Plugins" page or in the "IP Filter" menu in the "Settings" section of the Wordpress administration area.
