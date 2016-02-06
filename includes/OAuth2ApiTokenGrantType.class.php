<?php
/**
 * @file
 * Contains OAuth2ApiTokenGrantType class.
 */
use OAuth2\GrantType\GrantTypeInterface;

/**
 * Provide an API token grant type.
 *
 * This largely mimics \Oauth2\GrantType\RefreshToken, but removes the
 * requirement for the token to be tied to a specific client. It is also tightly
 * coupled to the oauth2_server and oauth2_api_token modules.
 */
class OAuth2ApiTokenGrantType implements GrantTypeInterface {

  private $token;

  public function getQuerystringIdentifier() {
    return 'api_token';
  }

  public function validateRequest(\OAuth2\RequestInterface $request, \OAuth2\ResponseInterface $response) {
    if (!$request->request("api_token")) {
      $response->setError(400, 'invalid_request', 'Missing parameter: "api_token" is required');

      return NULL;
    }

    if (!$token = $this->getApiToken($request->request("api_token"))) {
      $response->setError(400, 'invalid_grant', 'Invalid API token');

      return NULL;
    }

    if ($token['expires'] > 0 && $token["expires"] < time()) {
      $response->setError(400, 'invalid_grant', 'API token has expired');

      return NULL;
    }

    $this->token = $token;

    return TRUE;
  }

  public function getClientId() {
    // The API token may be used by any client.
    return NULL;
  }

  public function getUserId() {
    return isset($this->token['user_id']) ? $this->token['user_id'] : NULL;
  }

  public function getScope() {
    return isset($this->token['scope']) ? $this->token['scope'] : NULL;
  }

  public function createAccessToken(\OAuth2\ResponseType\AccessTokenInterface $accessToken, $client_id, $user_id, $scope) {
    return $accessToken->createAccessToken($client_id, $user_id, $scope, FALSE);
  }

  /**
   * Get and validate an API token.
   *
   * @param string $token_string
   *   The token string.
   * @param string $type
   *   The token type.
   *
   * @return array|FALSE
   *   Token information in the form expected by the oauth2-server-php library,
   *   or FALSE if the token is not valid.
   */
  protected function getApiToken($token_string, $type = 'api_token_exchange') {
    $tokens = oauth2_server_entity_load_by_properties('oauth2_server_token', array(
      'type' => $type,
      'token' => $token_string,
    ));
    if (!$tokens) {
      return FALSE;
    }

    /** @var \OAuth2ServerToken $token */
    $token = reset($tokens);

    // Validate the token type.
    if (!array_key_exists($token->type, oauth2_server_token_bundles())) {
      return FALSE;
    }

    $token_wrapper = entity_metadata_wrapper('oauth2_server_token', $token);
    $scopes = array();
    foreach ($token_wrapper->scopes as $scope_wrapper) {
      $scopes[] = $scope_wrapper->name->value();
    }
    // Return a token array in the format expected by the library.
    $token_array = array(
      'server' => $token_wrapper->client->server->raw(),
      'client_id' => $token_wrapper->client->client_key->value(),
      'user_id' => $token_wrapper->user->uid->value(),
      'refresh_token' => NULL,
      'expires' => (int) $token_wrapper->expires->value(),
      'scope' => implode(' ', $scopes),
    );
    if (module_exists('uuid')) {
      $token_array['user_uuid'] = $token_wrapper->user->uuid->value();
    }

    if ($token->last_access != REQUEST_TIME) {
      $token->last_access = REQUEST_TIME;
      $token->save();
    }

    return $token_array;
  }
}
