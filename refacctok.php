<?php
require 'globals.php';
require 'oauth_helper.php';

// Fill in the next 3 variables.
$old_access_token='A=KdfjadlskfjSDFGG.ertklsioerkjhSDFGkjlhasdfik345k34897SDFgklhe4kljhdSGKLjhsdfg.mcxkhdfSGKHsdfgkjeroI.REsdFGSFDg.sdfgiwresdfgsfhg.gh.tyu.ghfj.dfghfsdg.fgsdg.sdfgiretkjsfdgkjlhertiuysdfgkjhsdfgkljertkjhsdfguyert8743508972345lkjhsdfi8g89sdfg89sdfg908sdfg897sdfg8sdfg734jk25kljhwdkjlhsdfgkjlhsfdgkjlhsdfgjkhsdfgkjhsfdgiuywert87425ksdkjhlsdfgkjlhsdfgjklcxbm.cxvb.asfdkljadsflk.jasldkj3452387wert98sdfg8sdfg897sdfg890sdfgpoiret.lsdfgkljsdfgiwret_sfgkjhmnsdfgjkcvbmsdfglkjhewrtiusdfgjkhsdfgiuret87245lkjhdsfg.mnvbkisdfwertrwt.42534wertwgsdfg.cxvbsfdgsdfg.rwetwert.452435wertwretwer.wertwergtsdfgsdfg.sdfgsdfgrewtwret4252345wtdfgsdfg.sdfgsdfgsdfgewrtwert23452345wertwgsdfgfdrtyfhdgsdfgsdfgrewtwertsdfgdfgrt2rwersdfgdfgretrwefgrwtwertwertweryrwywertwertfsgfsdgsdferw3452twresdfgwretwert45wrtertrtg-';
$old_token_secret='o2345w980945353478594867g3454l45lk324wrd';
$oauth_session_handle='kj435kj.lkjlkj.ksdfgdfi44.dsfgkoert908435lkjglgs';

// Refresh the access token using HTTP GET and HMAC-SHA1 signature
$retarr = refresh_access_token(OAUTH_CONSUMER_KEY, OAUTH_CONSUMER_SECRET,
                               $old_access_token, $old_token_secret,
                               $oauth_session_handle, false, true, true);
if (! empty($retarr)) {
  list($info, $headers, $body, $body_parsed) = $retarr;
  if ($info['http_code'] == 200 && !empty($body)) {
      print "Use oauth_token as the token for all of your API calls:\n" .
          rfc3986_decode($body_parsed['oauth_token']) . "\n";
  }
}

exit(0);

/**
 * Refresh an access token using an expired request token
 * @param string $consumer_key obtained when you registered your app
 * @param string $consumer_secret obtained when you registered your app
 * @param string $old_access_token obtained previously
 * @param string $old_token_secret obtained previously
 * @param string $oauth_session_handle obtained previously
 * @param bool $usePost use HTTP POST instead of GET (default false)
 * @param bool $useHmacSha1Sig use HMAC-SHA1 signature (default false)
 * @return response string with token or empty array on error
 */
function refresh_access_token($consumer_key, $consumer_secret, $old_access_token, $old_token_secret, $oauth_session_handle, $usePost=false, $useHmacSha1Sig=true, $passOAuthInHeader=true)
{
  $retarr = array();  // return value
  $response = array();

  $url = 'https://api.login.yahoo.com/oauth/v2/get_token';
  $params['oauth_version'] = '1.0';
  $params['oauth_nonce'] = mt_rand();
  $params['oauth_timestamp'] = time();
  $params['oauth_consumer_key'] = $consumer_key;
  $params['oauth_token'] = $old_access_token;
  $params['oauth_session_handle'] = $oauth_session_handle;

  // compute signature and add it to the params list
  if ($useHmacSha1Sig) {
    $params['oauth_signature_method'] = 'HMAC-SHA1';
    $params['oauth_signature'] =
      oauth_compute_hmac_sig($usePost? 'POST' : 'GET', $url, $params,
                             $consumer_secret, $old_token_secret);
  } else {
    $params['oauth_signature_method'] = 'PLAINTEXT';
    $params['oauth_signature'] =
      oauth_compute_plaintext_sig($consumer_secret, $old_token_secret);
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
    logit("refacctok:INFO:request_url:$request_url");
    logit("refacctok:INFO:post_body:$query_parameter_string");
    $headers[] = 'Content-Type: application/x-www-form-urlencoded';
    $response = do_post($request_url, $query_parameter_string, 443, $headers);
  } else {
    $request_url = $url . ($query_parameter_string ?
                           ('?' . $query_parameter_string) : '' );
    logit("refacctok:INFO:request_url:$request_url");
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
