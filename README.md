# WP-Simple-Security
Simple Wordpress Security plugin for preventing comment spam and brute force attacks.

### Installation
* Load the wp-simple-security folder into your WP plugins directory and activate the plugin in the WP panel

## General WP Protections
* Exits bad requests early to prevent attacks from consuming a large amount of server resources
* Implements an HTTP tarpit against bad login requests to deter attackers and waste their time.
https://github.com/msigley/PHP-HTTP-Tarpit
  * The default is to send "Access Denied" messages on bad requests.
  * If you wish to enable the HTTP tarpit, add ```define('SIMPLE_SECURITY_USE_TARPIT', true);``` into your wp-config.php file.
* Sanitizes the version query arguement on .css and .js files to prevent version fingerprinting.
  * If you wish to customize the version number,  add ```define('CSSJSVERSION', 'version_number');``` into your wp-config.php file.
* Completely disables the XMLRPC API.
* Block external wp-cron.php requests if not using ALTERNATE_WP_CRON. This prevents potential DDOS vectors.
* Removes the WP version from the site header to prevent version fingerprinting.
* Disables the author query var to prevent user enumeration.

## WP Admin Protections
* Access to WP Admin area is blocked unless current user has the 'edit_posts' capability.

## Anti Spam Features
* Completely disables trackbacks.
* Limits the length of all fields on a comment form to prevent SQL injection.
* Adds nonce protection to comment forms.
* Adds a hidden captcha field to all comment forms.
* Removes bad comment author urls from comment listings.
* Spam requests are forwarded to a honeypot script.
  * If you wish to enable this feature, add ```define('SIMPLE_SECURITY_PROJECT_HONEY_POT_URL', '<honeypot_url>');``` into your wp-config.php file.
  * You can obtain a honeypot script by joining Project Honey Pot here: https://www.projecthoneypot.org/index.php
* All non-GET requests are checked for the following:
  * Common headless browser user agent strings.
  * Unsafe referer urls.
  * Bad IP reputation with the http:BL service.
    * If you wish to enable this feature, add ```define('SIMPLE_SECURITY_PROJECT_HONEY_POT_HTTP_BL_ACCESS_KEY', '<http:BL_access_key>');``` into your wp-config.php file.
    * You can read more about the http:BL service here: https://www.projecthoneypot.org/httpbl_api.php

## Login Form Protections
### Login Form Nonce Verification
* Adds a nonce field to the the wp-login.php form.
* Protects the wp-login.php form from external POST requests. This makes brute force attacks more difficult.
### Hidden Login Form
* Hides the wp-login.php form from public view.
* Protects the wp-login.php form from brute force attacks by adding a second layer of authentication.
#### How to use the hidden login form
1. Add ```define('SIMPLE_SECURITY_LOGIN_TOKEN_NAME', 'token_name');``` into your wp-config.php file.
2. Add ```define('SIMPLE_SECURITY_LOGIN_TOKEN_VALUE', 'token_value');``` into your wp-config.php file.
3. You login form can now only be accessed via the following url:
```https://example.com/wp-login.php?token_name=token_value```

## IP Blocker
* Blocks all requests to your site for one hour from IPs that have made 5 or more bad XMLRPC API or login form requests in the last 30 minutes.
* Supports IPv4 and IPv6 addresses.
* Blocked visitors will receive a message stating their IP has been blocked with a link to unblock their IP address.
* Blocked visitors that attempt to manipulate the unblock system recieve a permanent hour block.
### How to use the IP Blocker
1. Add ```define('SIMPLE_SECURITY_USE_IP_BLOCKER', true);``` into your wp-config.php file.
2. Add ```define('SIMPLE_SECURITY_BLOCK_INTERNAL_IPS', true);``` into your wp-config.php file if you wish to block internal and reserved IP ranges. The default is to not block these IP ranges.

## Whitelisted IPs
* Prevents a list of IP addresses from being sent to the tarpit or from being blocked by the IP Blocker.
* IPs on this list will still recieve access denied messages on bad requests.
### How to whitelist IPs
1. If you are using PHP 7 or above:
  a. Add ```
  define('SIMPLE_SECURITY_WHITELISTED_IPS', 
   array(
    '127.0.0.1',
    '192.168.10.0/20',
    '::1'
   )
  );``` into your wp-config.php file.
2. If you are using PHP 5.6:
  a. Add ```
  define('SIMPLE_SECURITY_WHITELISTED_IPS', 
   serialize(
    array(
     '127.0.0.1',
     '192.168.10.0/20',
     '::1'
    )
   )
  );``` into your wp-config.php file.

IPv4 addresses, IPv6 addresses, and IPv4 CIDR blocks are supported.
  
