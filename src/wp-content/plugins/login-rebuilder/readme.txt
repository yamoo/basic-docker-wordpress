=== Login rebuilder ===
Contributors: tmatsuur
Donate link: https://elearn.jp/wpman/column/login-rebuilder.html
Tags: login secure
Requires at least: 3.2.0
Tested up to: 5.0.0
Stable tag: 2.5.1
License: GPLv2 or later
License URI: http://www.gnu.org/licenses/gpl-2.0.html

This plug-in arranges the login page of a unique name.

== Description ==

Have not you experienced unjust access to wp-login.php? If this plug-in is used, a unique login page will be arranged to your site, and unlawful access will be reduced.

= Some features: =

* This plug-in arranges the login page of a unique name.
* When accessed by wp-login.php, some correspondence methods are offered.
* To limit the functionality of XML-RPC.

= Support =

* Japanese - https://elearn.jp/wpman/column/login-rebuilder.html

= Translators =

* Japanese(ja) - [Takenori Matsuura](https://12net.jp/)

You can send your own language pack to me.

Please contact to me.

* https://12net.jp/ (ja)
* email to takenori.matsuura[at]gmail.com
* @tmatsuur on twitter.

= Contributors =

* [Takenori Matsuura](https://12net.jp/)

== Installation ==

1. A plug-in installation screen is displayed on the WordPress admin panel.
2. It installs it in `wp-content/plugins`.
3. The plug-in is made effective.
4. You will find `Login rebuilder` submenu in `Settings` menu.
5. Please enter `New login file`, and choose `working`. Next, please click `Save Changes` button.
6. `Login file for subscriber` is optional. It becomes a page to which only subscribers can log in there.

== Frequently Asked Questions ==

= Is a `wp-login.php` file unnecessary? =

`wp-login.php` is used in this plug-in. Please do not delete `wp-login.php`.

= Even if it accessed a `wp-admin` directory, it became impossible to login.  =

Even if it accesses a `wp-admin` directory before login, it becomes impossible to log in, when this plug-in is effective. It is for not telling outside about a new login page.

= A new login page can be used even if this plug-in is invalid. =

Please delete the file, when a new login page becomes unnecessary.

= It became impossible to login from a new login page. =

Please delete the new login page file, this plug-in returns during preparation.

= Can I set the login page of the only administrators? =

If it is version 1.4.0 or later, you can choose the role of non-administrator for the `Secondary login file`.

= Does this plugin support Nginx? =

Yes, this plugin works well on Nginx.

== Screenshots ==

1. This plug-in menu.
2. This plug-in settings.
3. Widget on the dashboard.
4. This plug-in XML-RPC settings.
5. Other settings.
6. Lock file settings.

== Changelog ==

= 2.5.1 =
* Bug fix: Fixed an issue where valid IP address could not be stored in the log under certain conditions.

= 2.5.0 =
* New: Added authentication lock by specified file.

= 2.4.4 =
* Bug fix: Activation fails in a multisite environment where program files are installed in a subdirectory.

= 2.4.3 =
* The 'wp-login.php' has been changed so that 'confirmaction' is passed through only in version 4.9.6 or later.

= 2.4.2 =
* Set the original confirmation URL in the body of the user request mail.

= 2.4.1 =
* New: Add oembed setting.
* Changed: Display the user name after urldecode at login log.

= 2.4.0 =
* New: Add `Access to author page`: Access to the author page can be restricted.

= 2.3.0 =
* New: Log data can now be downloaded.

= 2.2.0 =
* New: Add other settings: Notify by email when the administrator login.

= 2.1.0 =
* New: Add other settings: The error message when login, is changed to the ambiguous content(WordPress Version 4.5 or later effective). / Authentication using a email address and a password is prohibited.

= 2.0.0 =
* New: XML-RPC settings. (WordPress Version 3.5 or later effective)

= 1.4.5 =
* Bug fix [important]: Changed the process of AJAX request.

= 1.4.4 =
* Added the widget that displays the log on the dashboard for administrators.

= 1.4.3 =
* `wp_secondary_login_url` method added.

= 1.4.2 =
* Bug fix [important]: Changed the process of AJAX request.

= 1.4.1 =
* Bug fix: A parameter of the function was adjusted.

= 1.4.0 =
* `Login file for subscriber` has changed the name to `Secondary login file`. `Secondary login file` will function as the login file for subscribers in the same way as before. In addition, the administrator can choose the role of login possible user.

= 1.3.1 =
* Bug fix: Password reset available.

= 1.3.0 =
* Login file is able to place in any directory.

= 1.2.3 =
* Changed the specification for the validity period of the property page.

= 1.2.2 =
* When expired, Display the reload button.

= 1.2.1 =
* Property page is now valid for 30 minutes.

= 1.2.0 =
* Bug fix [important]: It was coped with about CSRF.
 * New: Added logging.

= 1.1.3 =
* Bug fix:
 1.It corrected so that a post password could be used.

= 1.1.2 =
* Bug fix:
 1.A source code for debugging was deleted.

= 1.1.1 =
* Bug fix:
 1.Avoid fatal errors with a few plugins that were incorrectly calling functions too early.

= 1.1.0 =
* Login page for subscriber is available.

= 1.0.3 =
* Bug fix:
 1.A few array key name was corrected.
 2.The URL of properties form was corrected.

= 1.0.2 =
* Bug fix:
 1.The fault which has not recognized an alternative login file correctly in a part of server environments was coped with.

= 1.0.1 =
* Bug fix:
 1.Wrong URL was corrected at plugins.php.
 2.The operation at the time of invalid access became normal.

= 1.0.0 =
* The first release.

== Credits ==

This plug-in is not guaranteed though the user of WordPress can freely use this plug-in free of charge regardless of the purpose.
The author must acknowledge the thing that the operation guarantee and the support in this plug-in use are not done at all beforehand.

== Contact ==

email to takenori.matsuura[at]gmail.com
twitter @tmatsuur
