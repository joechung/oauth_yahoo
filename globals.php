<?php
/**
 * Globals and utilities for OAuth Examaples package
 */

// Fill in the next two constants
define('OAUTH_CONSUMER_KEY', 'REPLACE_ME');
define('OAUTH_CONSUMER_SECRET', 'REPLACE_ME');

$progname = $argv[0];
$debug = 0; // Set to 1 for verbose debugging output

function logit($msg,$preamble=true)
{
  // If you get timezone warnings from PHP, then
  // fill in the correct timezone, and uncomment the next line.
  //date_default_timezone_set('America/Los_Angeles');
  $now = date(DateTime::ISO8601, time());
  error_log(($preamble ? "+++${now}:" : '') . $msg);
}

/**
 * Do an HTTP GET
 * @param string $url
 * @param int $port (optional)
 * @param array $headers an array of HTTP headers (optional)
 * @return array ($info, $header, $response) on success or empty array on error.
 */
function do_get($url, $port=80, $headers=NULL)
{
  $retarr = array();  // Return value

  $curl_opts = array(CURLOPT_URL => $url,
                     CURLOPT_PORT => $port,
                     CURLOPT_POST => false,
                     CURLOPT_SSL_VERIFYHOST => false,
                     CURLOPT_SSL_VERIFYPEER => false,
                     CURLOPT_RETURNTRANSFER => true);

  if ($headers) { $curl_opts[CURLOPT_HTTPHEADER] = $headers; }

  $response = do_curl($curl_opts);

  if (! empty($response)) { $retarr = $response; }

  return $retarr;
}

/**
 * Do an HTTP POST
 * @param string $url
 * @param int $port (optional)
 * @param array $headers an array of HTTP headers (optional)
 * @return array ($info, $header, $response) on success or empty array on error.
 */
function do_post($url, $postbody, $port=80, $headers=NULL)
{
  $retarr = array();  // Return value

  $curl_opts = array(CURLOPT_URL => $url,
                     CURLOPT_PORT => $port,
                     CURLOPT_POST => true,
                     CURLOPT_SSL_VERIFYHOST => false,
                     CURLOPT_SSL_VERIFYPEER => false,
                     CURLOPT_POSTFIELDS => $postbody,
                     CURLOPT_RETURNTRANSFER => true);

  if ($headers) { $curl_opts[CURLOPT_HTTPHEADER] = $headers; }

  $response = do_curl($curl_opts);

  if (! empty($response)) { $retarr = $response; }

  return $retarr;
}

/**
 * Make a curl call with given options.
 * @param array $curl_opts an array of options to curl
 * @return array ($info, $header, $response) on success or empty array on error.
 */
function do_curl($curl_opts)
{
  global $debug;

  $retarr = array();  // Return value

  if (! $curl_opts) {
    if ($debug) { logit("do_curl:ERR:curl_opts is empty"); }
    return $retarr;
  }

  // Open curl session
  $ch = curl_init();
  if (! $ch) {
    if ($debug) { logit("do_curl:ERR:curl_init failed"); }
    return $retarr;
  }

  // Set curl options that were passed in
  curl_setopt_array($ch, $curl_opts);

  // Ensure that we receive full header
  curl_setopt($ch, CURLOPT_HEADER, true);

  if ($debug) {
    curl_setopt($ch, CURLINFO_HEADER_OUT, true);
    curl_setopt($ch, CURLOPT_VERBOSE, true);
  }

  // Send the request and get the response
  ob_start();
  $response = curl_exec($ch);
  $curl_spew = ob_get_contents();
  ob_end_clean();
  if ($debug && $curl_spew) {
    logit("do_curl:INFO:curl_spew begin");
    logit($curl_spew, false);
    logit("do_curl:INFO:curl_spew end");
  }

  // Check for errors
  if (curl_errno($ch)) {
    $errno = curl_errno($ch);
    $errmsg = curl_error($ch);
    if ($debug) { logit("do_curl:ERR:$errno:$errmsg"); }
    curl_close($ch);
    unset($ch);
    return $retarr;
  }

  if ($debug) {
    logit("do_curl:DBG:header sent begin");
    $header_sent = curl_getinfo($ch, CURLINFO_HEADER_OUT);
    logit($header_sent, false);
    logit("do_curl:DBG:header sent end");
  }

  // Get information about the transfer
  $info = curl_getinfo($ch);

  // Parse out header and body
  $header_size = curl_getinfo($ch, CURLINFO_HEADER_SIZE);
  $header = substr($response, 0, $header_size);
  $body = substr($response, $header_size );

  // Close curl session
  curl_close($ch);
  unset($ch);

  if ($debug) {
    logit("do_curl:DBG:response received begin");
    if (!empty($response)) { logit($response, false); }
    logit("do_curl:DBG:response received end");
  }

  // Set return value
  array_push($retarr, $info, $header, $body);

  return $retarr;
}

/**
 * Pretty print some JSON
 * @param string $json The packed JSON as a string
 * @param bool $html_output true if the output should be escaped
 * (for use in HTML)
 * @link http://us2.php.net/manual/en/function.json-encode.php#80339
 */
function json_pretty_print($json, $html_output=false)
{
  $spacer = '  ';
  $level = 1;
  $indent = 0; // current indentation level
  $pretty_json = '';
  $in_string = false;

  $len = strlen($json);

  for ($c = 0; $c < $len; $c++) {
    $char = $json[$c];
    switch ($char) {
    case '{':
    case '[':
      if (!$in_string) {
        $indent += $level;
        $pretty_json .= $char . "\n" . str_repeat($spacer, $indent);
      } else {
        $pretty_json .= $char;
      }
      break;
    case '}':
    case ']':
      if (!$in_string) {
        $indent -= $level;
        $pretty_json .= "\n" . str_repeat($spacer, $indent) . $char;
      } else {
        $pretty_json .= $char;
      }
      break;
    case ',':
      if (!$in_string) {
        $pretty_json .= ",\n" . str_repeat($spacer, $indent);
      } else {
        $pretty_json .= $char;
      }
      break;
    case ':':
      if (!$in_string) {
        $pretty_json .= ": ";
      } else {
        $pretty_json .= $char;
      }
      break;
    case '"':
      if ($c > 0 && $json[$c-1] != '\\') {
        $in_string = !$in_string;
      }
    default:
      $pretty_json .= $char;
      break;
    }
  }

  return ($html_output) ?
    '<pre>' . htmlentities($pretty_json) . '</pre>' :
    $pretty_json . "\n";
}
?>
