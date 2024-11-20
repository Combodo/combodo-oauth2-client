<?php
/*!
* Hybridauth
* https://hybridauth.github.io | https://github.com/hybridauth/hybridauth
*  (c) 2020 Hybridauth authors | https://hybridauth.github.io/license.html
*/

namespace Hybridauth\Provider;

use Hybridauth\Adapter\OAuth2;
use Hybridauth\Data;
use Hybridauth\Exception\InvalidApplicationCredentialsException;
use Hybridauth\Exception\UnexpectedApiResponseException;
use Hybridauth\User;

/**
 * Itop OAuth2 provider adapter.
 */
class Itop extends OAuth2
{
    /**
     * {@inheritdoc}
     */
    protected $scope = 'account_info.read';

    /**
     * {@inheritdoc}
     */
    protected $apiDocumentation = 'https://www.itophub.io/wiki/page?id=start';
	private string $username;
	private string $password;
	private string $version = "1.3";

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

		if (!$this->config->exists('username')) {
			throw new InvalidApplicationCredentialsException(
				'You must define a provider username'
			);
		}
		$this->username = $this->config->get('username');

		if (!$this->config->exists('password')) {
			throw new InvalidApplicationCredentialsException(
				'You must define a provider password'
			);
		}
		$this->password = $this->config->get('password');

		if ($this->config->exists('version')) {
			$this->version = $this->config->get('version');
		}

		$this->apiBaseUrl = $url . '/webservices/rest.php';

		$this->authorizeUrl = $this->apiBaseUrl . '/pages/exec.php?exec_module=authent-oauth&exec_page=auth.php';
		$this->accessTokenUrl = $this->authorizeUrl;
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
			'username' => $this->username,
			'password' => $this->password,
			'grant_type' => 'password',
			'redirect_uri' => $this->callback
		];

		if ($this->isRefreshTokenAvailable()) {
			$this->tokenRefreshParameters += [
				'client_id' => $this->clientId,
				'client_secret' => $this->clientSecret
			];
		}

        $this->apiRequestHeaders = [
	        'Content-Type' => 'application/json'
        ];

		$this->apiRequestParameters = [
		'version' => $this->version
		];

		$this->tokenExchangeHeaders = [
			'Content-Type' => 'application/json'
		];

		$this->tokenRefreshHeaders = [
			'Content-Type' => 'application/json'
		];
	}

    /**
     * {@inheritdoc}
     */
    public function getUserProfile()
    {
		$jsonData = <<<JSON
SELECT User WHERE login="$this->username"
JSON;

        $response = $this->apiRequest('', 'POST', [ 'json_data' => $jsonData ], [], true);

        $data = new Data\Collection($response);

        if (!$data->exists('code') || !$data->get('message') || !$data->get('objects')) {
            throw new UnexpectedApiResponseException('Provider API returned an unexpected response.');
        }

	    $code = $data->get('code');
	    $message = $data->get('message');
	    if ($code != 0){
		    throw new UnexpectedApiResponseException("Provider API returned an unexpected code (code: $code / message: $message).");
	    }

		if ($message != 'Found: 1'){
			throw new UnexpectedApiResponseException("Provider API returned an unexpected message (code: $code / message: $message).");
		}

	    $objects = $data->filter('objects');
		if (! is_array($objects) || count($objects) !=1){
			throw new UnexpectedApiResponseException("Provider API returned an unexpected objects (code: $code / message: $message).");
		}

		$userInfo = array_shift($objects);

        $userProfile = new User\Profile();

        $userProfile->identifier = $userInfo->get('login');
        $userProfile->firstName = $userInfo->get('first_name');
        $userProfile->lastName = $userInfo->get('last_name');
        $userProfile->email = $userInfo->get('email');
        $userProfile->language = $userInfo->get('language');
	    $userProfile->data = [
			'id' => $userInfo->get('id'),
			'org_id' => $userInfo->get('org_id'),
			'profile_list' => $userInfo->get('profile_list'),
			'class' => $userInfo->get('class'),
	    ];
        return $userProfile;
    }
}
