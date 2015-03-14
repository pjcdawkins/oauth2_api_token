<?php
/**
 * @file
 * Forms for the OAuth2 API Token module.
 */

/**
 * The API token editing form.
 *
 * @todo require password confirmation
 */
function oauth2_api_token_form($form, &$form_state, OAuth2ServerToken $token = NULL, $account = NULL) {
  form_load_include($form_state, 'inc', 'module', 'includes/oauth2_api_token.forms');

  $server_name = variable_get('oauth2_api_token_server');
  /** @var OAuth2Server $server */
  $server = $server_name ? oauth2_server_load($server_name) : NULL;
  if (!$server) {
    drupal_set_message(t('OAuth2 server not found'), 'error');
    watchdog('oauth2_api_token', 'OAuth2 server not found, or not configured', array(), WATCHDOG_ERROR);
    $form['#disabled'] = TRUE;
    return $form;
  }

  $account = $account ?: $GLOBALS['user'];

  /** @var OAuth2ServerToken $token */
  $token = $token ?: entity_get_controller('oauth2_server_token')->create(array(
    'type' => 'api_token',
    'uid' => $account->uid,
    'expires_in' => NULL,
    'is_new' => TRUE,
  ));

  $form_state['account'] = $account;
  $form_state['token'] = $token;

  // Add the Application field.
  field_attach_form('oauth2_server_token', $token, $form, $form_state, NULL, array(
    'field_name' => 'api_token_app',
  ));

  // Load all the scopes for the server.
  $api_scopes = variable_get('oauth2_api_token_scopes', array('account'));
  /** @var OAuth2ServerScope[] $server_scopes */
  $server_scopes = oauth2_server_entity_load_by_properties('oauth2_server_scope', array(
    'server' => $server->name,
  ));
  $default_scopes = array();
  $scope_options = array();
  foreach ($server_scopes as $scope) {
    if (in_array($scope->name, $api_scopes)) {
      $scope_id = $scope->internalIdentifier();
      $scope_options[$scope_id] = t('@name (@description)', array(
        '@name' => $scope->name,
        '@description' => $scope->description,
      ));
      if (!empty($token->is_new)) {
        $default_scopes[] = $scope_id;
      }
      // @todo check this
      elseif (in_array($scope_id, $token->wrapper()->scopes->value())) {
        $default_scopes[] = $scope_id;
      }
    }
  }

  if ($scope_options) {
    $form['scopes'] = array(
      '#type' => 'checkboxes',
      '#title' => t('Scopes'),
      '#options' => $scope_options,
      '#description' => t('Scopes restrict what the client is authorized to access using this API token.'),
      '#weight' => 90,
      '#default_value' => $default_scopes,
    );
  }

  $form['actions'] = array('#type' => 'actions', '#weight' => 100);
  $form['actions']['submit'] = array(
    '#type' => 'submit',
    '#value' => t('Create API token'),
  );

  $cancel_path = 'user/' . $account->uid . '/api-tokens';
  if (isset($_GET['destination'])) {
    $destination = drupal_get_destination();
    $cancel_path = $destination['destination'];
  }
  $form['actions']['cancel'] = array(
    '#type' => 'link',
    '#title' => t('Cancel'),
    '#href' => $cancel_path,
  );

  return $form;
}

/**
 * Validation callback for the API token form.
 */
function oauth2_api_token_form_validate(&$form, &$form_state) {
  field_attach_validate('oauth2_server_token', $form_state['token']);
}

/**
 * Submit callback for the API token form.
 */
function oauth2_api_token_form_submit(&$form, &$form_state) {
  $account = $form_state['account'];

  /** @var OAuth2ServerToken $token */
  $token = $form_state['token'];

  field_attach_submit('oauth2_server_token', $token, $form, $form_state);

  foreach ($form_state['values']['scopes'] as $scope_id) {
    $token->wrapper()->scopes[] = $scope_id;
  }

  $token->uid = $account->uid;

  // Force the expiry time to 19 January 2038: this is the easiest way to have
  // a never-expiring token, for now.
  // See https://github.com/bshaffer/oauth2-server-php/issues/166
  if (!isset($token->expires)) {
    $token->expires = 2147483647;
  }

  $access_token = new OAuth2ApiTokenAccessToken();

  $success = $access_token->saveApiToken($token);
  if ($success) {
    unset($token->is_new);
    drupal_set_message(t('Created API token for %application', array(
      '%application' => $token->wrapper()->api_token_app->value(),
    )));
    drupal_set_message(t('Copy this token. It will not be shown again.'), 'status');
    drupal_set_message(check_plain($token->token), 'status', FALSE);
  }
  else {
    drupal_set_message(t('Failed to save API token'), 'error');
  }

  $form_state['redirect'] = 'user/' . $account->uid . '/api-tokens';
}

/**
 * Confirmation form for deleting a token.
 */
function oauth2_api_token_delete_form($form, &$form_state, OAuth2ServerToken $token) {
  $account = oauth2_api_token_get_account($token);
  $form_state['account'] = $account;
  $form_state['token'] = $token;

  return confirm_form(
    $form,
    t('Are you sure you want to delete this token?'),
    'user/' . $account->uid . '/api-tokens'
  );
}

/**
 * Confirmation form for deleting a token.
 */
function oauth2_api_token_delete_form_submit($form, &$form_state) {
  /** @var OAuth2ServerToken $token */
  $token = $form_state['token'];
  $account = $form_state['account'];
  $token->delete();
  drupal_set_message(t('The API token was successfully deleted'));
  $form_state['redirect'] = 'user/' . $account->uid . '/api-tokens';
}
