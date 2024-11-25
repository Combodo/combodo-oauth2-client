<?php

namespace Combodo\iTop\Oauth2Client\HybridAuth;

use Combodo\iTop\Oauth2Client\Helper\Oauth2ClientException;
use Combodo\iTop\Oauth2Client\Helper\Oauth2ClientHelper;
use Combodo\iTop\Oauth2Client\Helper\Oauth2ClientLog;
use Exception;
use Hybridauth\Adapter\AdapterInterface;
use Hybridauth\Logger\Logger;
use ReflectionClass;
use utils;

class AdapterService {
	private static AdapterService $oInstance;
	private string $sName;
	private string $sProvider;
	private string $sProviderName;
	private AdapterInterface $oAuth2;

	protected function __construct() {
		Oauth2ClientLog::Enable();
	}

	final public static function GetInstance(): AdapterService {
		if (!isset(static::$oInstance)) {
			static::$oInstance = new static();
		}

		return static::$oInstance;
	}

	final public static function SetInstance(?AdapterService $oInstance): void {
		static::$oInstance = $oInstance;
	}

	/**
	 * @param string $sName
	 * @param string $sProvider provider class fqdn
	 *
	 * @return void
	 */
	public function Init(string $sName, string $sProvider) : void
	{
		Oauth2ClientLog::Debug(__FUNCTION__, null, [$sName, $sProvider]);
		$this->sName = $sName;
		$this->sProviderName = Oauth2ClientHelper::GetProviderName($sProvider);
		$this->sProvider = $sProvider;
	}

	public function InitOauth2(array $aConfig): void
	{
		try {
			$this->oAuth2 = AdapterInterfaceFactoryService::GetInstance()->GetAdapterInterface($this->sProviderName, $aConfig);
			$sAuthorizationState = $aConfig['authorization_state'] ?? null;
			if (utils::IsNotNullOrEmptyString($sAuthorizationState)){
				$this->oAuth2->getStorage()->set($this->sProviderName.'.authorization_state', $sAuthorizationState);
			}
		} catch (Exception $e) {
			throw new Oauth2ClientException(__FUNCTION__.': failed', 0, $e);
		}
	}

	public function Authenticate(array $aConfig) : void {
		Oauth2ClientLog::Debug(__FUNCTION__, null, $aConfig);
		$this->InitOauth2($aConfig);

		$this->oAuth2->disconnect();
		$this->oAuth2->authenticate();
	}

	public function AuthenticateFinish(array $aConfig) : array
	{
		Oauth2ClientLog::Debug(__FUNCTION__, null, $aConfig);
		$this->InitOauth2($aConfig);
		$this->oAuth2->authenticate();

		$aTokens = $this->oAuth2->getAccessToken();
		$aTokens['authorization_state'] = $this->GetAuthorizationState();

		Oauth2ClientLog::Debug(__FUNCTION__, null, $aTokens);
		return $aTokens;
	}

	public function RefreshToken(array $aConfig) : array
	{
		Oauth2ClientLog::Debug(__FUNCTION__, null, $aConfig);
		$this->InitOauth2($aConfig);

		// refresh tokens if needed
		$this->oAuth2->maintainToken();
		$hasAccessTokenExpired = $this->oAuth2->hasAccessTokenExpired();
		Oauth2ClientLog::Debug(__FUNCTION__, null, ['hasAccessTokenExpired' => $hasAccessTokenExpired ]);
		if ($hasAccessTokenExpired === true) {
			Oauth2ClientLog::Debug(__FUNCTION__, null, ['isRefreshTokenAvailable' => $this->oAuth2->isRefreshTokenAvailable() ]);
			$sResponse = $this->oAuth2->refreshAccessToken();
			if (is_null($sResponse)){
				throw new Oauth2ClientException("Refresh token not available");
			}

			Oauth2ClientLog::Debug(__FUNCTION__, null, ['refresh token response' => $sResponse ]);
		}

		$aTokens = $this->oAuth2->getAccessToken();
		$aTokens['authorization_state'] = $this->GetAuthorizationState();
		Oauth2ClientLog::Debug(__FUNCTION__, null, $aTokens);
		return $aTokens;
	}

	private function GetAuthorizationState() : string {
		if ($_SERVER['REQUEST_METHOD'] === 'POST'){
			$sAuthorizationState= utils::ReadPostedParam('state', '',utils::ENUM_SANITIZATION_FILTER_STRING);
		} else {
			$sAuthorizationState= utils::ReadParam('state', '', false, utils::ENUM_SANITIZATION_FILTER_STRING);
		}
		Oauth2ClientLog::Debug(__FUNCTION__, null, [$sAuthorizationState]);
		return $sAuthorizationState;
	}

	public function GetDefaultScope() : string {
		/** @noinspection OneTimeUseVariablesInspection */
		$oClass = new ReflectionClass($this->oAuth2);
		$oProperty = $oClass->getProperty('scope');
		$oProperty->setAccessible(true);
		return $oProperty->getValue($this->oAuth2);
	}
}
