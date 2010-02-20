<?php
require 'globals.php';
require 'oauth_helper.php';

// Fill in the next 3 variables.
$guid='X4323GFSERGF43454GSFGBCCB3';
$access_token='A=KdfjadlskfjSDFGG.ertklsioerkjhSDFGkjlhasdfik345k34897SDFgklhe4kljhdSGKLjhsdfg.mcxkhdfSGKHsdfgkjeroI.REsdFGSFDg.sdfgiwresdfgsfhg.gh.tyu.ghfj.dfghfsdg.fgsdg.sdfgiretkjsfdgkjlhertiuysdfgkjhsdfgkljertkjhsdfguyert8743508972345lkjhsdfi8g89sdfg89sdfg908sdfg897sdfg8sdfg734jk25kljhwdkjlhsdfgkjlhsfdgkjlhsdfgjkhsdfgkjhsfdgiuywert87425ksdkjhlsdfgkjlhsdfgjklcxbm.cxvb.asfdkljadsflk.jasldkj3452387wert98sdfg8sdfg897sdfg890sdfgpoiret.lsdfgkljsdfgiwret_sfgkjhmnsdfgjkcvbmsdfglkjhewrtiusdfgjkhsdfgiuret87245lkjhdsfg.mnvbkisdfwertrwt.42534wertwgsdfg.cxvbsfdgsdfg.rwetwert.452435wertwretwer.wertwergtsdfgsdfg.sdfgsdfgrewtwret4252345wtdfgsdfg.sdfgsdfgsdfgewrtwert23452345wertwgsdfgfdrtyfhdgsdfgsdfgrewtwertsdfgdfgrt2rwersdfgdfgretrwefgrwtwertwertweryrwywertwertfsgfsdgsdferw3452twresdfgwretwert45wrtertrtg-';
$access_token_secret='o2345w980945353478594867g3454l45lk324wrd';

$retarr = call_contact_api(OAUTH_CONSUMER_KEY, OAUTH_CONSUMER_SECRET,
                           $guid, $access_token, $access_token_secret, true);

exit(0);

/**
 * Call the Yahoo Contact API
 * @param string $consumer_key obtained when you registered your app
 * @param string $consumer_secret obtained when you registered your app
 * @param string $access_token obtained from get_request_token
 * @param string $access_token_secret obtained from get_request_token
 * @param bool $passOAuthInHeader pass the OAuth credentials in HTTP header
 * @return response string with token or empty array on error
 */
function call_contact_api($consumer_key, $consumer_secret, $guid, $access_token, $access_token_secret, $passOAuthInHeader=false)
{
  $retarr = array();  // return value

  $url = 'http://social.yahooapis.com/v1/user/' . $guid . '/contacts;count=5?format=json';
  $params['oauth_version'] = '1.0';
  $params['oauth_nonce'] = mt_rand();
  $params['oauth_timestamp'] = time();
  $params['oauth_consumer_key'] = $consumer_key;
  $params['oauth_token'] = $access_token;

  // compute hmac-sha1 signature and add it to the params list
  $params['oauth_signature_method'] = 'HMAC-SHA1';
  $params['oauth_signature'] =
      oauth_compute_hmac_sig('GET', $url, $params,
                             $consumer_secret, $access_token_secret);

  // encode, sort, and build query parameter string
  $query_parameter_string = oauth_http_build_query($params);

  // POST or GET the request
  if ($passOAuthInHeader) {
    $request_url = $url;
    logit("call_contact_api:INFO:request_url:$request_url");
    $header = build_oauth_header($params);
    $headers[] = $header;
    $response = do_get($request_url, 80, $headers);
  } else {
    $request_url = $url . '&' . $query_parameter_string;
    logit("call_contact_api:INFO:request_url:$request_url");
    $response = do_get($request_url);
  }

  // extract successful response
  if (! empty($response)) {
    list($info, $header, $body) = $response;
    if ($body) {
      logit("call_contact_api:INFO:response:");
      print(json_pretty_print($body));
    }
  }

  return $retarr;
}
?>
