<?php
require 'globals.php';
require 'oauth_helper.php';

// Fill in the next 3 variables.
$request_token='w9giroe';
$request_token_secret='z3a2abcd3ag1c543fg987d1c2222a333popa24ee';
$oauth_verifier= 'lrifnc';

$retarr = get_access_token(OAUTH_CONSUMER_KEY, OAUTH_CONSUMER_SECRET,
                           $request_token, $request_token_secret,
                           $oauth_verifier);
if (! empty($retarr) && $retarr['oauth_token']) {
  print "Use oauth_token as the token for all of your API calls:\n" .
    rfc3986_decode($retarr['oauth_token']) . "\n";
}

exit(0);

/**
 * Get an access token using a request token and OAuth Verifier
 * @param string $consumer_key obtained when you registered your app
 * @param string $consumer_secret obtained when you registered your app
 * @param string $request_token obtained from get_request_token
 * @param string $request_token_secret obtained from get_request_token
 * @param string $oauth_verifier
 * @param bool $usePost use HTTP POST instead of GET (default false)
 * @param bool $useHmacSha1Sig use HMAC-SHA1 signature (default false)
 * @return response string with token or empty array on error
 */
function get_access_token($consumer_key, $consumer_secret, $request_token, $request_token_secret, $oauth_verifier, $usePost=false, $useHmacSha1Sig=false)
{
  $retarr = array();  // return value

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

  // encode, sort, and build query parameter string
  $query_parameter_string = oauth_http_build_query($params);

  // POST or GET the request
  if ($usePost) {
    $request_url = $url;
    logit("get_access_token:INFO:request_url:$request_url");
    logit("get_access_token:INFO:post_body:$query_parameter_string");
    $headers[] = 'Content-Type: application/x-www-form-urlencoded';
    $response = do_post($request_url, $query_parameter_string, 443, $headers);
  } else {
    $request_url = $url . '?' . $query_parameter_string;
    logit("get_access_token:INFO:request_url:$request_url");
    $response = do_get($request_url, 443);
  }

  // extract successful response
  if (! empty($response)) {
    list($info, $header, $body) = $response;
    $retarr = oauth_parse_str($body);
    if (! empty($retarr)) {
      logit("get_access_token:INFO:response:");
      print_r($retarr);
    }
  }

  return $retarr;
}
?>
