<?php
/**
 * @file
 * Contains OAuth2ApiTokenAccessToken class.
 */
use OAuth2\ResponseType\AccessToken;

/**
 * Override \OAuth2\ResponseType\AccessToken to support API tokens.
 */
class OAuth2ApiTokenAccessToken extends AccessToken {

  /**
   * Removes all the config arguments as they are irrelevant.
   */
  public function __construct() {
    parent::__construct(new \Drupal\oauth2_server\Storage(), NULL, array(
      'access_lifetime' => 0,
      'refresh_token_lifetime' => 0,
    ));
  }

  /**
   * Save a new API token.
   *
   * @param OAuth2ServerToken $token
   *   A token entity with pre-populated 'client_id', 'uid', and 'scopes'
   *   properties.
   *
   * @return bool
   *   TRUE on success, FALSE on failure.
   */
  public function saveApiToken(OAuth2ServerToken $token) {
    foreach (array('client_id', 'uid', 'scopes') as $property) {
      if (!isset($token->$property)) {
        throw new \RuntimeException('Missing required API token property: ' . $property);
      }
    }

    if (!isset($token->token)) {
      $token->token = $this->generateAccessToken();
    }

    if (!isset($token->type)) {
      $token->type = 'api_token_exchange';
    }

    switch ($token->type) {
      // For personal access tokens, force the expiry time to 19 January 2038.
      // This is the easiest way to have a never-expiring token, for now. See
      // https://github.com/bshaffer/oauth2-server-php/issues/166
      case 'api_token_access':
        $token->expires = 2147483647;
        break;

      // For exchangeable tokens, ensure they cannot be used directly for
      // authentication by setting their expiry time to 0.
      case 'api_token_exchange':
        $token->expires = 0;
        break;
    }

    return $token->save();
  }

}
