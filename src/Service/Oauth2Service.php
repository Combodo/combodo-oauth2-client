<?php

namespace Combodo\iTop\Oauth2Client\Service;

use Combodo\iTop\Oauth2Client\Helper\Oauth2ClientException;
use Combodo\iTop\Oauth2Client\Helper\Oauth2ClientLog;
use Combodo\iTop\Oauth2Client\HybridAuth\AdapterService;
use Combodo\iTop\Oauth2Client\Model\Oauth2ClientService;
use Exception;
use Hybridauth\Data\Collection;
use Hybridauth\HttpClient\HttpClientInterface;
use Hybridauth\Storage\StorageInterface;
use Oauth2Client;

/**
 * OAuth 2.0 client APi
 *
 * @api
 * @package
 */
class Oauth2Service
{
	private static Oauth2Service $oInstance;
	private string $sName;
	private string $sProvider;

	protected function __construct()
	{
		Oauth2ClientLog::Enable();
	}

	final public static function GetInstance(): Oauth2Service
	{
		if (!isset(static::$oInstance)) {
			static::$oInstance = new static();
		}

		return static::$oInstance;
	}

	final public static function SetInstance(?Oauth2Service $oInstance): void
	{
		static::$oInstance = $oInstance;
	}

	/**
	 * Initialize the API with the name and provider name of the OAuth IdP
	 *
	 * @api
	 *
	 * @param string $sName Registered entry name chosen for this connection
	 * @param string $sProvider Provider name
	 * @param ?HttpClientInterface $oHttpClient
	 * @param ?StorageInterface $storage
	 *
	 * @return void
	 * @throws \Combodo\iTop\Oauth2Client\Helper\Oauth2ClientException
	 */
	public function Init(string $sName, string $sProvider, ?HttpClientInterface $oHttpClient=null, ?StorageInterface $oStorage=null)
	{
		try {
			Oauth2ClientLog::Debug(__FUNCTION__, null, [$sName, $sProvider]);
			$this->sName = $sName;
			$this->sProvider = $sProvider;
			Oauth2ClientService::GetInstance()->InitClient($this->sName, $this->sProvider);
			AdapterService::GetInstance()->Init($this->sName, $this->sProvider, $oHttpClient, $oStorage);
		} catch (Oauth2ClientException $e) {
			throw $e;
		} catch (Exception $e) {
			throw new Oauth2ClientException(__FUNCTION__.': failed', 0, $e);
		}
	}

	/**
	 * Initialize the API with the corresponding Oauth2Client object
	 *
	 * @api
	 *
	 * @param \Oauth2Client $oOauth2Client
	 * @param ?HttpClientInterface $oHttpClient
	 * @param ?StorageInterface $storage
	 *
	 * @return void
	 * @throws \Combodo\iTop\Oauth2Client\Helper\Oauth2ClientException
	 */
	public function InitByOauth2Client(Oauth2Client $oOauth2Client, ?HttpClientInterface $oHttpClient=null, ?StorageInterface $oStorage=null): void
	{
		try {
			Oauth2ClientLog::Debug(__FUNCTION__, null, [$oOauth2Client->GetKey()]);
			$this->sName = $oOauth2Client->Get('name');
			$this->sProvider = $oOauth2Client->Get('provider');
			Oauth2ClientService::GetInstance()->InitClientByOauth2Client($oOauth2Client);
			AdapterService::GetInstance()->Init($this->sName, $this->sProvider, $oHttpClient, $oStorage);
		} catch (Oauth2ClientException $e) {
			throw $e;
		} catch (Exception $e) {
			throw new Oauth2ClientException(__FUNCTION__.': failed', 0, $e);
		}
	}

	/**
	 * Authenticate the connection with the IdP
	 * The connection is first disconnected then connected again
	 *
	 * @api
	 * @return string
	 * @throws \Combodo\iTop\Oauth2Client\Helper\Oauth2ClientException
	 */
	public function Authenticate(): string
	{
		try {
			Oauth2ClientLog::Debug(__FUNCTION__, null, [$this->sName, $this->sProvider]);
			$aConfig = Oauth2ClientService::GetInstance()->GetAuthenticateConfiguration();
			AdapterService::GetInstance()->Authenticate($aConfig);

			return $this->AuthenticateFinish();
		} catch (Oauth2ClientException $e) {
			throw $e;
		} catch (Exception $e) {
			throw new Oauth2ClientException(__FUNCTION__.': failed', 0, $e);
		}
	}

	/**
	 * Finish the authentication process with the response from the IdP
	 *
	 * @api
	 * @return string
	 * @throws \Combodo\iTop\Oauth2Client\Helper\Oauth2ClientException
	 */
	public function AuthenticateFinish(?string $sAuthorizationStateForTestingOnly=null): string
	{
		try {
			Oauth2ClientLog::Debug(__FUNCTION__, null, [$this->sName, $this->sProvider]);
			$aConfig = Oauth2ClientService::GetInstance()->GetAuthenticateConfiguration();
			if (! is_null($sAuthorizationStateForTestingOnly)){
				//simulate below code when calling AuthenticateBegin()->getAuthorizeUrl()
				//  $this->storeData('authorization_state', $this->AuthorizeUrlParameters['state']);
				$aConfig['authorization_state'] = $sAuthorizationStateForTestingOnly;
			}
			$aTokenResponse = AdapterService::GetInstance()->AuthenticateFinish($aConfig);
			$sDefaultScope = AdapterService::GetInstance()->GetDefaultScope();
			Oauth2ClientService::GetInstance()->SaveTokens($aTokenResponse, $sDefaultScope);

			return Oauth2ClientService::GetInstance()->GetAccessToken();
		} catch (Oauth2ClientException $e) {
			throw $e;
		} catch (Exception $e) {
			throw new Oauth2ClientException(__FUNCTION__.': failed', 0, $e);
		}
	}

	/**
	 * Get the access token to use in communication with IdP
	 *
	 * @api
	 * @return string
	 * @throws \Combodo\iTop\Oauth2Client\Helper\Oauth2ClientException
	 */
	public function GetAccessToken(): string
	{
		try {
			Oauth2ClientLog::Debug(__FUNCTION__, null, [$this->sName, $this->sProvider]);
			$sToken = Oauth2ClientService::GetInstance()->GetAccessToken();

			if (!Oauth2ClientService::GetInstance()->IsExpired()) {
				return $sToken;
			}

			$aConfig = Oauth2ClientService::GetInstance()->GetRefreshTokenConfiguration();
			$aTokenResponse = AdapterService::GetInstance()->RefreshToken($aConfig);
			$sDefaultScope = AdapterService::GetInstance()->GetDefaultScope();
			Oauth2ClientService::GetInstance()->SaveTokens($aTokenResponse, $sDefaultScope);

			return Oauth2ClientService::GetInstance()->GetAccessToken();
		} catch (Oauth2ClientException $e) {
			throw $e;
		} catch (Exception $e) {
			throw new Oauth2ClientException(__FUNCTION__.': failed', 0, $e);
		}
	}

	/**
	 * Get the access token to use in communication with IdP
	 *
	 * @api
	 * @return \Hybridauth\User\Profile
	 * @throws \Combodo\iTop\Oauth2Client\Helper\Oauth2ClientException
	 */
	public function GetUserProfile(): \Hybridauth\User\Profile
	{
		try {
			Oauth2ClientLog::Debug(__FUNCTION__, null, [$this->sName, $this->sProvider]);

			//refresh token if needed
			$this->GetAccessToken();

			$aConfig = Oauth2ClientService::GetInstance()->GetRefreshTokenConfiguration();

			return AdapterService::GetInstance()->GetUserProfile($aConfig);
		} catch (Oauth2ClientException $e) {
			throw $e;
		} catch (Exception $e) {
			throw new Oauth2ClientException(__FUNCTION__.': failed', 0, $e);
		}
	}

	/**
	 * Get the access token to use in communication with IdP
	 *
	 * @api
	 *
	 * @param string $sUrl
	 * @param string $sMethod
	 * @param array $aParameters
	 * @param array $aHeaders
	 * @param bool $bMultipart
	 *
	 * @return \Hybridauth\Data\Collection
	 * @throws \Combodo\iTop\Oauth2Client\Helper\Oauth2ClientException
	 */
	public function ApiRequest(string $sUrl, string $sMethod = 'GET', array $aParameters = [], array $aHeaders = [], bool $bMultipart = false): Collection
	{
		try {
			Oauth2ClientLog::Debug(__FUNCTION__, null, [$this->sName, $this->sProvider]);

			//refresh token if needed
			$this->GetAccessToken();

			$aConfig = Oauth2ClientService::GetInstance()->GetRefreshTokenConfiguration();

			return AdapterService::GetInstance()->ApiRequest($aConfig, $sUrl, $sMethod, $aParameters, $aHeaders, $bMultipart);
		} catch (Oauth2ClientException $e) {
			throw $e;
		} catch (Exception $e) {
			throw new Oauth2ClientException(__FUNCTION__.': failed', 0, $e);
		}
	}
}
