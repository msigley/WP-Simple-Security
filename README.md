# WP-Simple-Security
Simple Wordpress Security plugin for preventing comment spam and brute force attacks.

### Installation
* Load the wp-simple-security folder into your WP plugins directory and activate the plugin in the WP panel

## General WP Protections
* Exits bad requests early to prevent attacks from consuming a large amount of server resources
* Implements an HTTP tarpit against bad login requests to deter attackers and waste their time.
https://github.com/msigley/PHP-HTTP-Tarpit
  * The default is to send "Access Denied" messages on bad requests.
  * If you wish to enable the HTTP tarpit, add ```defined('SIMPLE_SECURITY_USE_TARPIT', true);``` into your wp-config.php file.
* Sanitizes the version query arguement on .css and .js files to prevent version fingerprinting.
  * If you wish to customize the version number,  add ```defined('CSSJSVERSION', 'version_number');``` into your wp-config.php file.
* Completely disables the XMLRPC API.
* Removes the WP version from the site header to prevent version fingerprinting.
* Completely disables trackbacks.
* Limits the length of all fields on a comment form to prevent SQL injection.
* Disables the author query var to prevent user enumeration.
* Removes bad comment author urls from comment listings.

## Login Form Protections
### Login Form Nonce Verification
* Adds a nonce field to the the wp-login.php form.
* Protects the wp-login.php form from external POST requests. This makes brute force attacks more difficult.
### Hidden Login Form
* Hides the wp-login.php form from public view.
* Protects the wp-login.php form from brute force attacks by adding a second layer of authentication.
#### How to use the hidden login form
1. Add ```defined('SIMPLE_SECURITY_LOGIN_TOKEN_NAME', 'token_name');``` into your wp-config.php file.
2. Add ```defined('SIMPLE_SECURITY_LOGIN_TOKEN_NAME', 'token_vale');``` into your wp-config.php file.
3. You login form can now only be accessed via the following url:
```https://example.com/wp-login.php?token_name=token_value```

## IP Blocker
* Blocks all requests to your site for one hour from IPs that have made 5 or more bad XMLRPC API or login form requests in the last 30 minutes.
* Supports IPv4 and IPv6 addresses.
* Blocked visitors will receive a message stating their IP has been blocked with a link to unblock their IP address.
* Blocked visitors that attempt to manipulate the unblock system recieve a permenant hour block.
### How to use the IP Blocker
1. Add ```defined('SIMPLE_SECURITY_USE_IP_BLOCKER', true);``` into your wp-config.php file.
2. Add ```defined('SIMPLE_SECURITY_BLOCK_INTERNAL_IPS', true);``` into your wp-config.php file if you wish to block internal and reserved IP ranges. The default is to not block these IP ranges.
