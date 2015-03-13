<?php

class OAuth2ApiTokenAccessToken extends \OAuth2\ResponseType\AccessToken {

  /**
   * Overrides \OAuth2\ResponseType\AccessToken::__construct().
   *
   * Removes all the arguments as they are irrelevant.
   */
  public function __construct() {
    parent::__construct(new \Drupal\oauth2_server\Storage(), NULL, array(
      'access_lifetime' => 0,
    ));
  }

  /**
   * Save a new API token.
   *
   * @param OAuth2ServerToken $token
   *   A token entity with pre-populated 'type', 'uid', and 'scopes'
   *   properties.
   *
   * @return bool
   *   TRUE on success, FALSE on failure.
   */
  public function saveApiToken(OAuth2ServerToken $token) {
    foreach (array('uid', 'scopes') as $property) {
      if (empty($token->$property)) {
        throw new \RuntimeException('Missing required API token property: ' . $property);
      }
    }

    // @todo set an appropriate client ID
    $token->client_id = NULL;

    $token->token = $this->generateAccessToken();
    $token->type = 'api_token';
    $token->expires = 0;

    return $token->save();
  }

}
