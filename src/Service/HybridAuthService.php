<?php
/**
 * @copyright   Copyright (C) 2010-2024 Combodo SARL
 * @license     http://opensource.org/licenses/AGPL-3.0
 */

namespace Combodo\iTop\Oauth2Client\Service;

use Combodo\iTop\Oauth2Client\Helper\Oauth2ClientException;
use Combodo\iTop\Oauth2Client\Helper\Oauth2ClientLog;
use Exception;
use Hybridauth\Adapter\OAuth2;
use Hybridauth\Hybridauth;
use Hybridauth\Logger\Logger;
use utils;

class HybridAuthService
{
	/** @var ?HybridAuthService */
	private static $oInstance;

	private function __construct()
	{
		Oauth2ClientLog::Enable();
	}

	public static function GetInstance(): HybridAuthService
	{
		if (!isset(static::$oInstance)) {
			static::$oInstance = new HybridAuthService();
		}

		return static::$oInstance;
	}

	public static function SetInstance(?HybridAuthService $oInstance): void
	{
		static::$oInstance = $oInstance;
	}

	public function GetOauth2(array $aConfig, string $sProviderName, string $sAuthorizationState): OAuth2
	{
		try {
			Oauth2ClientLog::Debug(__FUNCTION__, null, $aConfig);
			$oLogger = new Logger(Oauth2ClientLog::GetHybridauthDebugMode(), APPROOT.'log/hybridauth.log');

			$oHybridauth = new Hybridauth($aConfig, null, null, $oLogger);
			/** @var OAuth2 $oAuth2 */
			$oAuth2 = $oHybridauth->getAdapter($sProviderName);
			if (utils::IsNotNullOrEmptyString($sAuthorizationState)){
				$this->storeData($oAuth2, 'authorization_state', $sAuthorizationState);
			}
			return $oAuth2;
		} catch (Exception $e) {
			throw new Oauth2ClientException(__FUNCTION__.': failed', 0, $e);
		}
	}

	public function storeData(OAuth2 $oAuth2, string $sKey, $sValue) : void
	{
		$oAuth2->getStorage()->set($sKey, $sValue);
	}

	public function getStoredData(OAuth2 $oAuth2, string $sKey) : mixed
	{
		return $oAuth2->getStorage()->get($sKey);
	}
}
