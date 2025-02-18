<?php
/*!
* Hybridauth
* https://hybridauth.github.io | https://github.com/hybridauth/hybridauth
*  (c) 2020 Hybridauth authors | https://hybridauth.github.io/license.html
*/

namespace Hybridauth\Provider;

use Hybridauth\Adapter\OAuth2;
use Hybridauth\Data\Collection;
use Hybridauth\Exception\Exception;
use Hybridauth\Exception\InvalidApplicationCredentialsException;
use Hybridauth\Exception\UnexpectedApiResponseException;
use Hybridauth\User\Profile;

/**
 * Itop Oauth2 Connect provider adapter.
 *
 * Example:
 *         'Keycloak' => [
 *             'enabled' => true,
 *             'url' => 'your-itop-url', // depending on your setup you might need to add '/auth'
 *             'realm' => 'your-realm',
 *              'environnement' => 'your-environnement', //usually production
 *             'keys' => [
 *                 'id' => 'client-id',
 *                 'secret' => 'client-secret'
 *             ]
 *         ]
 *
 */
class Itop extends OAuth2
{
	/**
	 * {@inheritdoc}
	 */
	protected $scope = 'REST/JSON Synchro Oauth2/GetUser';

	/**
	 * {@inheritdoc}
	 */
	protected $apiDocumentation = 'https://www.itophub.io/wiki/page?id=start';
	private string $version = "1.3";
	private string $environnement = "production";
	protected $tokenExchangeMethod = 'POST';
	protected string $getUserUrl;

	/**
	 * {@inheritdoc}
	 */
	protected function configure()
	{
		parent::configure();
		if (!$this->config->exists('url')) {
			throw new InvalidApplicationCredentialsException(
				'You must define a provider url'
			);
		}
		$url = $this->config->get('url');

		if ($this->config->exists('version')) {
			$this->version = $this->config->get('version');
		}

		if ($this->config->exists('environnement')) {
			$this->environnement = $this->config->get('environnement');
		}

		$this->apiBaseUrl = $url;

		$sTokenBaseUrl = sprintf("%s/env-%s/%s/", $url, $this->environnement, "authent-token");
		$this->authorizeUrl = $sTokenBaseUrl."authorize.php";
		$this->accessTokenUrl = $sTokenBaseUrl.'token.php';
		$this->getUserUrl = $sTokenBaseUrl.'get_user.php';
	}

	/**
	 * {@inheritdoc}
	 */
	protected function initialize()
	{
		parent::initialize();

		$this->tokenExchangeParameters = [
			'client_id' => $this->clientId,
			'client_secret' => $this->clientSecret,
			'grant_type' => 'authorization_code',
			'redirect_uri' => $this->callback,
		];

		$refreshToken = $this->getStoredData('refresh_token');
		if (!empty($refreshToken)) {
			$this->tokenRefreshParameters = [
				'client_id' => $this->clientId,
				'client_secret' => $this->clientSecret,
				'grant_type' => 'refresh_token',
				'refresh_token' => $refreshToken,
				'redirect_uri' => $this->callback,
			];
		}

		$this->apiRequestParameters = [
			'version' => $this->version,
		];
	}

	/**
	 * {@inheritdoc}
	 */
	public function getUserProfile()
	{
		$response = $this->apiRequest($this->getUserUrl, 'POST');

		$data = new Collection($response);

		$userProfile = new Profile();

		$userProfile->email = $data->get('email');
		$userProfile->firstName = $data->get('firstName');
		$userProfile->lastName = $data->get('lastName');
		$userProfile->displayName = $data->get('displayName');
		$userProfile->identifier = $data->get('identifier');
		$userProfile->displayName = $data->get('language');

		// Collect organization claim if provided in the IDToken
		if ($data->exists('organization')) {
			$userProfile->data['organization'] = $data->get('organization');
		}

		return $userProfile;
	}
}
