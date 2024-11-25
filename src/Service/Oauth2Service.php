<?php

namespace Combodo\iTop\Oauth2Client\Service;

use Combodo\iTop\Oauth2Client\Helper\Oauth2ClientException;
use Combodo\iTop\Oauth2Client\Helper\Oauth2ClientLog;
use Combodo\iTop\Oauth2Client\HybridAuth\AdapterService;
use Combodo\iTop\Oauth2Client\Model\Oauth2ClientService;
use Exception;
use Oauth2Client;

class Oauth2Service {
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
	 * @api
	 * @param string $sName
	 * @param string $sProvider
	 *
	 * @return void
	 */
	public function Init(string $sName, string $sProvider)
	{
		Oauth2ClientLog::Debug(__FUNCTION__, null, [$sName, $sProvider]);
		$this->sName = $sName;
		$this->sProvider = $sProvider;
		Oauth2ClientService::GetInstance()->InitClient($this->sName, $this->sProvider);
		AdapterService::GetInstance()->Init($this->sName, $this->sProvider);
	}

	/**
	 * @api
	 * @param \Oauth2Client $oOauth2Client
	 *
	 * @return void
	 */
	public function InitByOauth2Client(Oauth2Client $oOauth2Client) : void
	{
		Oauth2ClientLog::Debug(__FUNCTION__, null, [$oOauth2Client]);
		$this->sName = $oOauth2Client->Get('name');
		$this->sProvider = $oOauth2Client->Get('provider');
		Oauth2ClientService::GetInstance()->InitClientByOauth2Client($oOauth2Client);
		AdapterService::GetInstance()->Init($this->sName, $this->sProvider);
	}

	/**
	 * @api
	 * @return string
	 * @throws \Combodo\iTop\Oauth2Client\Helper\Oauth2ClientException
	 */
	public function Authenticate() : string
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
	 * @api
	 * @return string
	 * @throws \Combodo\iTop\Oauth2Client\Helper\Oauth2ClientException
	 */
	public function AuthenticateFinish() : string
	{
		Oauth2ClientLog::Debug(__FUNCTION__, null, [$this->sName, $this->sProvider]);
		$aConfig = Oauth2ClientService::GetInstance()->GetAuthenticateConfiguration();
		$aTokenResponse = AdapterService::GetInstance()->AuthenticateFinish($aConfig);
		$sDefaultScope = AdapterService::GetInstance()->GetDefaultScope();

		Oauth2ClientService::GetInstance()->SaveTokens($aTokenResponse, $sDefaultScope);
		return Oauth2ClientService::GetInstance()->GetAccessToken();
	}

	/**
	 * @api
	 * @return string
	 * @throws \Combodo\iTop\Oauth2Client\Helper\Oauth2ClientException
	 */
	public function GetAccessToken() : string
	{
		Oauth2ClientLog::Debug(__FUNCTION__, null, [$this->sName, $this->sProvider]);
		$sToken = Oauth2ClientService::GetInstance()->GetAccessToken();
		if (is_null($sToken)){
			throw new Oauth2ClientException("Oauth2 never initialized");
		}

		//expired token
		if (! Oauth2ClientService::GetInstance()->IsExpired()){
			return $sToken;
		}

		$aConfig = Oauth2ClientService::GetInstance()->GetRefreshTokenConfiguration();
		$aTokenResponse = AdapterService::GetInstance()->RefreshToken($aConfig);
		$sDefaultScope = AdapterService::GetInstance()->GetDefaultScope();

		Oauth2ClientService::GetInstance()->SaveTokens($aTokenResponse, $sDefaultScope);
		return Oauth2ClientService::GetInstance()->GetAccessToken();
	}

	/**
	 * @api
	 * @param \Combodo\iTop\Oauth2Client\Service\Oauth2Client $oOauth2Client
	 *
	 * @return string
	 */
	public function GetAccessTokenByOauth2Client(\Oauth2Client $oOauth2Client) : string
	{
		$this->InitByOauth2Client($oOauth2Client);
		return $this->GetAccessToken();
	}
}
