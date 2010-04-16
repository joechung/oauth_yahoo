<?php
require 'globals.php';
require 'oauth_helper.php';

// Fill in the next 3 variables.
$guid='X4323GFSERGF43454GSFGBCCB3';
$access_token='A=KdfjadlskfjSDFGG.ertklsioerkjhSDFGkjlhasdfik345k34897SDFgklhe4kljhdSGKLjhsdfg.mcxkhdfSGKHsdfgkjeroI.REsdFGSFDg.sdfgiwresdfgsfhg.gh.tyu.ghfj.dfghfsdg.fgsdg.sdfgiretkjsfdgkjlhertiuysdfgkjhsdfgkljertkjhsdfguyert8743508972345lkjhsdfi8g89sdfg89sdfg908sdfg897sdfg8sdfg734jk25kljhwdkjlhsdfgkjlhsfdgkjlhsdfgjkhsdfgkjhsfdgiuywert87425ksdkjhlsdfgkjlhsdfgjklcxbm.cxvb.asfdkljadsflk.jasldkj3452387wert98sdfg8sdfg897sdfg890sdfgpoiret.lsdfgkljsdfgiwret_sfgkjhmnsdfgjkcvbmsdfglkjhewrtiusdfgjkhsdfgiuret87245lkjhdsfg.mnvbkisdfwertrwt.42534wertwgsdfg.cxvbsfdgsdfg.rwetwert.452435wertwretwer.wertwergtsdfgsdfg.sdfgsdfgrewtwret4252345wtdfgsdfg.sdfgsdfgsdfgewrtwert23452345wertwgsdfgfdrtyfhdgsdfgsdfgrewtwertsdfgdfgrt2rwersdfgdfgretrwefgrwtwertwertweryrwywertwertfsgfsdgsdferw3452twresdfgwretwert45wrtertrtg-';
$access_token_secret='o2345w980945353478594867g3454l45lk324wrd';

// Call Contact API
$retarr = callcontact(OAUTH_CONSUMER_KEY, OAUTH_CONSUMER_SECRET,
                      $guid, $access_token, $access_token_secret,
                      false, true);

exit(0);

/**
 * Call the Yahoo Contact API
 * @param string $consumer_key obtained when you registered your app
 * @param string $consumer_secret obtained when you registered your app
 * @param string $guid obtained from getacctok
 * @param string $access_token obtained from getacctok
 * @param string $access_token_secret obtained from getacctok
 * @param bool $usePost use HTTP POST instead of GET
 * @param bool $passOAuthInHeader pass the OAuth credentials in HTTP header
 * @return response string with token or empty array on error
 */
function callcontact($consumer_key, $consumer_secret, $guid, $access_token, $access_token_secret, $usePost=false, $passOAuthInHeader=true)
{
  $retarr = array();  // return value
  $response = array();

  $url = 'http://social.yahooapis.com/v1/user/' . $guid . '/contacts;count=5';
  $params['format'] = 'json';
  $params['view'] = 'compact';
  $params['oauth_version'] = '1.0';
  $params['oauth_nonce'] = mt_rand();
  $params['oauth_timestamp'] = time();
  $params['oauth_consumer_key'] = $consumer_key;
  $params['oauth_token'] = $access_token;

  // compute hmac-sha1 signature and add it to the params list
  $params['oauth_signature_method'] = 'HMAC-SHA1';
  $params['oauth_signature'] =
      oauth_compute_hmac_sig($usePost? 'POST' : 'GET', $url, $params,
                             $consumer_secret, $access_token_secret);

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
    logit("callcontact:INFO:request_url:$request_url");
    logit("callcontact:INFO:post_body:$query_parameter_string");
    $headers[] = 'Content-Type: application/x-www-form-urlencoded';
    $response = do_post($request_url, $query_parameter_string, 80, $headers);
  } else {
    $request_url = $url . ($query_parameter_string ?
                           ('?' . $query_parameter_string) : '' );
    logit("callcontact:INFO:request_url:$request_url");
    $response = do_get($request_url, 80, $headers);
  }

  // extract successful response
  if (! empty($response)) {
    list($info, $header, $body) = $response;
    if ($body) {
      logit("callcontact:INFO:response:");
      print(json_pretty_print($body));
    }
    $retarr = $response;
  }

  return $retarr;
}
?>
