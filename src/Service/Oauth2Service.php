<?php

namespace Combodo\iTop\Oauth2Client\Service;

use Combodo\iTop\Oauth2Client\Helper\Oauth2ClientException;
use Combodo\iTop\Oauth2Client\Helper\Oauth2ClientLog;
use Combodo\iTop\Oauth2Client\HybridAuth\AdapterService;
use Combodo\iTop\Oauth2Client\Model\ConfigService;
use Combodo\iTop\Oauth2Client\Model\Oauth2ClientService;
use Exception;

class Oauth2Service {
	private static Oauth2Service $oInstance;
	private string $sName;
	private string $sProvider;

	protected function __construct()
	{
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

	public function Init(string $sName, string $sProvider)
	{
		Oauth2ClientLog::Debug(__FUNCTION__, null, [$sName, $sProvider]);
		$this->sName = $sName;
		$this->sProvider = $sProvider;
		Oauth2ClientService::GetInstance()->InitClient($this->sName, $this->sProvider);
		AdapterService::GetInstance()->Init($this->sName, $this->sProvider);
	}

	public function Authenticate() : string
	{
		try {
			$aConfig = Oauth2ClientService::GetInstance()->GetAuthenticateConfiguration();
			AdapterService::GetInstance()->Authenticate($aConfig);

			return $this->AuthenticateFinish();
		} catch (Oauth2ClientException $e) {
			throw $e;
		} catch (Exception $e) {
			throw new Oauth2ClientException(__FUNCTION__.': failed', 0, $e);
		}
	}

	public function AuthenticateFinish() : string
	{
		$aConfig = Oauth2ClientService::GetInstance()->GetAuthenticateConfiguration();
		$aTokenResponse = AdapterService::GetInstance()->AuthenticateFinish($aConfig);

		Oauth2ClientService::GetInstance()->SaveTokens($aTokenResponse);
		return Oauth2ClientService::GetInstance()->GetAccessToken();
	}

	public function GetAccessToken() : string
	{
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

		Oauth2ClientService::GetInstance()->SaveTokens($aTokenResponse);
		return Oauth2ClientService::GetInstance()->GetAccessToken();
	}
}
