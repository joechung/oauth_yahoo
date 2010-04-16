<?php
require 'globals.php';
require 'oauth_helper.php';

// Fill in the next 3 variables.
$request_token='w9giroe';
$request_token_secret='z3a2abcd3ag1c543fg987d1c2222a333popa24ee';
$oauth_verifier= 'lrifnc';

// Get the access token using HTTP GET and HMAC-SHA1 signature
$retarr = get_access_token(OAUTH_CONSUMER_KEY, OAUTH_CONSUMER_SECRET,
                           $request_token, $request_token_secret,
                           $oauth_verifier, false, true, true);
if (! empty($retarr)) {
  list($info, $headers, $body, $body_parsed) = $retarr;
  if ($info['http_code'] == 200 && !empty($body)) {
      print "Use oauth_token as the token for all of your API calls:\n" .
          rfc3986_decode($body_parsed['oauth_token']) . "\n";
  }
}

exit(0);

/**
 * Get an access token using a request token and OAuth Verifier.
 * @param string $consumer_key obtained when you registered your app
 * @param string $consumer_secret obtained when you registered your app
 * @param string $request_token obtained from getreqtok
 * @param string $request_token_secret obtained from getreqtok
 * @param string $oauth_verifier obtained from step 3
 * @param bool $usePost use HTTP POST instead of GET
 * @param bool $useHmacSha1Sig use HMAC-SHA1 signature
 * @param bool $passOAuthInHeader pass OAuth credentials in HTTP header
 * @return array of response parameters or empty array on error
 */
function get_access_token($consumer_key, $consumer_secret, $request_token, $request_token_secret, $oauth_verifier, $usePost=false, $useHmacSha1Sig=true, $passOAuthInHeader=true)
{
  $retarr = array();  // return value
  $response = array();

  $url = 'https://api.login.yahoo.com/oauth/v2/get_token';
  $params['oauth_version'] = '1.0';
  $params['oauth_nonce'] = mt_rand();
  $params['oauth_timestamp'] = time();
  $params['oauth_consumer_key'] = $consumer_key;
  $params['oauth_token']= $request_token;
  $params['oauth_verifier'] = $oauth_verifier;

  // compute signature and add it to the params list
  if ($useHmacSha1Sig) {
    $params['oauth_signature_method'] = 'HMAC-SHA1';
    $params['oauth_signature'] =
      oauth_compute_hmac_sig($usePost? 'POST' : 'GET', $url, $params,
                             $consumer_secret, $request_token_secret);
  } else {
    $params['oauth_signature_method'] = 'PLAINTEXT';
    $params['oauth_signature'] =
      oauth_compute_plaintext_sig($consumer_secret, $request_token_secret);
  }

  // Pass OAuth credentials in a separate header or in the query string
  if ($passOAuthInHeader) {
    $query_parameter_string = oauth_http_build_query($params, true);
    $header = build_oauth_header($params, "yahooapis.com");
    $headers[] = $header;
  } else {
    $query_parameter_string = oauth_http_build_query($params);
  }

  // POST or GET the request
  if ($usePost) {
    $request_url = $url;
    logit("getacctok:INFO:request_url:$request_url");
    logit("getacctok:INFO:post_body:$query_parameter_string");
    $headers[] = 'Content-Type: application/x-www-form-urlencoded';
    $response = do_post($request_url, $query_parameter_string, 443, $headers);
  } else {
    $request_url = $url . ($query_parameter_string ?
                           ('?' . $query_parameter_string) : '' );
    logit("getacctok:INFO:request_url:$request_url");
    $response = do_get($request_url, 443, $headers);
  }

  // extract successful response
  if (! empty($response)) {
    list($info, $header, $body) = $response;
    $body_parsed = oauth_parse_str($body);
    if (! empty($body_parsed)) {
      logit("getacctok:INFO:response_body_parsed:");
      print_r($body_parsed);
    }
    $retarr = $response;
    $retarr[] = $body_parsed;
  }

  return $retarr;
}
?>
