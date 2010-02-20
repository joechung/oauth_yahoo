<?php
require 'globals.php';
require 'oauth_helper.php';

// Callback can either be 'oob' or a url whose domain must match
// the domain that you entered when registering your application
$callback='oob';

// Get the request token using HTTP POST and HMAC-SHA1 signature
$retarr = get_request_token(OAUTH_CONSUMER_KEY, OAUTH_CONSUMER_SECRET,
                            $callback, true, true);
if (! empty($retarr) && $retarr['xoauth_request_auth_url']) {
  print "Have the user go to xoauth_request_auth_url to authorize your app\n" .
    rfc3986_decode($retarr['xoauth_request_auth_url']) . "\n";
}

exit(0);

/**
 * Get a request token.
 * @param string $consumer_key obtained when you registered your app
 * @param string $consumer_secret obtained when you registered your app
 * @param string $callback callback url can be the string 'oob'
 * @param bool $usePost use HTTP POST instead of GET (default false)
 * @param bool $useHmacSha1Sig use HMAC-SHA1 signature (default false)
 * @return array of response parameters or empty array on error
 */
function get_request_token($consumer_key, $consumer_secret, $callback, $usePost=false, $useHmacSha1Sig=false)
{
  $retarr = array();  // return value

  $url = 'https://api.login.yahoo.com/oauth/v2/get_request_token';
  $params['oauth_version'] = '1.0';
  $params['oauth_nonce'] = mt_rand();
  $params['oauth_timestamp'] = time();
  $params['oauth_consumer_key'] = $consumer_key;
  $params['oauth_callback'] = $callback;

  // compute signature and add it to the params list
  if ($useHmacSha1Sig) {
    $params['oauth_signature_method'] = 'HMAC-SHA1';
    $params['oauth_signature'] =
      oauth_compute_hmac_sig($usePost? 'POST' : 'GET', $url, $params,
                             $consumer_secret, null);
  } else {
    $params['oauth_signature_method'] = 'PLAINTEXT';
    $params['oauth_signature'] =
      oauth_compute_plaintext_sig($consumer_secret, null);
  }

  // encode, sort, and build query parameter string
  $query_parameter_string = oauth_http_build_query($params);

  // POST or GET the request
  if ($usePost) {
    $request_url = $url;
    logit("get_request_token:INFO:request_url:$request_url");
    logit("get_request_token:INFO:post_body:$query_parameter_string");
    $headers[] = 'Content-Type: application/x-www-form-urlencoded';
    $response = do_post($request_url, $query_parameter_string, 443, $headers);
  } else {
    $request_url = $url . '?' . $query_parameter_string;
    logit("get_request_token:INFO:request_url:$request_url");
    $response = do_get($request_url, 443);
  }

  // extract successful response
  if (! empty($response)) {
    list($info, $header, $body) = $response;
    $retarr = oauth_parse_str($body);
    if (! empty($retarr)) {
      logit("get_request_token:INFO:response:");
      print_r($retarr);
    }
  }

  return $retarr;
}
?>
