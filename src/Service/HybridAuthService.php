<?php

namespace Combodo\iTop\Oauth2Client\Service;

use Combodo\iTop\Oauth2Client\Helper\Oauth2ClientException;
use Combodo\iTop\Oauth2Client\Helper\Oauth2ClientLog;
use Exception;
use Hybridauth\Adapter\OAuth2;
use Hybridauth\Hybridauth;
use Hybridauth\Logger\Logger;

class HybridAuthService {
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

	public function GetOauth2(array $aConfig, string $sProviderName) : OAuth2
	{
		try {
			Oauth2ClientLog::Debug(__FUNCTION__, null, $aConfig);
			$oLogger = new Logger(Oauth2ClientLog::GetHybridauthDebugMode(), APPROOT.'log/hybridauth.log');

			$oHybridauth = new Hybridauth($aConfig, null, null, $oLogger);
			/** @var OAuth2 $oAuth2 */
			$oAuth2 = $oHybridauth->getAdapter($sProviderName);
			return $oAuth2;
		} catch (Exception $e) {
			throw new Oauth2ClientException(__FUNCTION__.': failed', 0, $e);
		}
	}
}
