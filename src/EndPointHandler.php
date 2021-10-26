<?php

namespace TahaKhram\LaravelAdb2cOpenid;

use Illuminate\Http\Request;

use GuzzleHttp\Client;
use GuzzleHttp\Exception\RequestException;

class EndPointHandler {

  private $metadata = "";

  public function __construct($policy_name) {
    $this->getMetadata($policy_name);
  }

  // Given a B2C policy name, constructs the metadata endpoint
  // and fetches the metadata from that endpoint
  public function getMetadata($policy_name) {
    $metadata_endpoint = config('azure.endpoint_begin') . $policy_name;
    $this->metadata = json_decode($this->getEndpointData($metadata_endpoint), true);
  }

  // Fetches the data at an endpoint using a HTTP GET request
  public function getEndpointData($uri) {
    return file_get_contents($uri);
  }


  // Obtains the authorization endpoint from the metadata
  // and adds the necessary query arguments
  public function getAuthorizationEndpoint() {
    $authorization_endpoint = $this->metadata["authorization_endpoint"].
                                            '&client_id='.env('AZ_CLIENT_ID').
                                            '&response_type='.urlencode(env('AZ_RESPONSE_TYPE')).
                                            '&redirect_uri='.urlencode(env('AZ_REDIRECT_URI')).
                                            '&response_mode=form_post'.
                                            '&scope='.urlencode(env('AZ_SCOPE')).
                                            '&prompt=login';
    return $authorization_endpoint;
  }


  // Using a HTTP POST request, sends data to the endpoint and receives the response
  public function postEndpointData($uri, $postdata) {
    $result = $this->http_post($uri, $postdata);
    return $result;
  }
  public function prepare_headers($headers) {
    return
    implode('', array_map(function($key, $value) {
            return "$key: $value\r\n";
        }, array_keys($headers), array_values($headers))
    );
  }

  public function http_post($url, $data, $ignore_errors = false) {
    $data_query = http_build_query($data);
    $data_len = strlen($data_query);

    $headers = array(
      'Content-Type' => 'application/x-www-form-urlencoded',
      'Content-Length' => $data_len
    );

    $response =
    file_get_contents($url, false, stream_context_create(
        array('http' => array(
                  'method' => 'POST',
                  'header' => $this->prepare_headers($headers),
                //   'content' => $data_query,
        )
        ), $data
    ));

    return (false === $response) ? false :
        array(
            'headers' => $http_response_header,
            'body' => $response
        );
  }



  // Returns the value of the issuer claim from the metadata
  public function getIssuer() {
    return $this->metadata['issuer'];
  }

  // Returns the value of the jwks_uri claim from the metadata
  public function getJwksUri() {
    return $this->metadata['jwks_uri'];
  }

  // Returns the data at the jwks_uri page
  public function getJwksUriData() {
    $jwks_uri = $this->getJwksUri();
    $key_data = $this->getEndpointData($jwks_uri);
    return $key_data;
  }



  // Obtains the end session endpoint from the metadata
  // and adds the necessary query arguments
  public function getEndSessionEndpoint() {
    $end_session_endpoint = $this->metadata['end_session_endpoint'] . 
                                '&redirect_uri='.urlencode(env('AZ_REDIRECT_URI'));
    return $end_session_endpoint;
  }

  // Obtains the token endpoint from the metadata
  public function getTokenEndpoint() {
    return $this->metadata['token_endpoint'];
  }
}