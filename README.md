# WP-Simple-Security
Simple Wordpress Security plugin for preventing comment spam and brute force attacks.

### Installation
* Load the wp-simple-security folder into your WP plugins directory and activate the plugin in the WP panel

## Login Form Protections
* Protects the wp-login.php form from brute force attacks
* Hides the wp-login.php form from public view
* Exits bad login requests early to prevent attacks from consuming a large ammount of server resources
* Implements an HTTP tarpit against bad login requests to deter attackers and waste their time.
https://github.com/msigley/PHP-HTTP-Tarpit

### How to use the login form protections
1. Add ```defined('SIMPLE_SECURITY_LOGIN_TOKEN_NAME', 'token_name');``` into your wp-config.php file.
2. Add ```defined('SIMPLE_SECURITY_LOGIN_TOKEN_NAME', 'token_vale');``` into your wp-config.php file.
3. You login form can now only be accessed via the following url:
```https://example.com/wp-login.php?token_name=token_value```
4. If you wish to enable the HTTP tarpit, add ```defined('SIMPLE_SECURITY_USE_TARPIT', true);``` into your wp-config.php file.

## General WP Protections
* Sanitizes the version query arguement on .css and .js files to prevent version fingerprinting.
  * If you wish to customize the version number,  add ```defined('CSSJSVERSION', 'version_number');``` into your wp-config.php file.
* Completely disables the XMLRPC API.
* Removes the WP version from the site header to prevent version fingerprinting.
* Completely disables trackbacks.
* Limits the length of all fields on a comment form to prevent SQL injection.
* Disables the author query var to prevent user enumeration.
* Removes bad comment author urls from comment listings.
