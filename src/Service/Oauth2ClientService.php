<?php
/**
 * @copyright   Copyright (C) 2010-2024 Combodo SARL
 * @license     http://opensource.org/licenses/AGPL-3.0
 */

namespace Combodo\iTop\Oauth2Client\Service;

use Combodo\iTop\Oauth2Client\Helper\Oauth2ClientLog;
use Combodo\iTop\Oauth2Client\Model\ConfigService;
use Hybridauth\Adapter\AdapterInterface;
use Hybridauth\Hybridauth;
use Hybridauth\Logger\Logger;

class Oauth2ClientService
{
	/** @var Oauth2ClientService */
	private static $oInstance;

	private function __construct()
	{
		Oauth2ClientLog::Enable();
	}

	public static function GetInstance(): Oauth2ClientService
	{
		if (!isset(static::$oInstance)) {
			static::$oInstance = new Oauth2ClientService();
		}

		return static::$oInstance;
	}

	/**
	 * @param string $sName
	 * @param string $sProvider
	 *
	 * @return \Hybridauth\Adapter\AdapterInterface: when already connected returns the object. otherwise redirection occurs to IDP
	 * @throws \Combodo\iTop\Oauth2Client\Helper\Oauth2ClientException
	 * @throws \Hybridauth\Exception\InvalidArgumentException
	 * @throws \Hybridauth\Exception\RuntimeException
	 * @throws \Hybridauth\Exception\UnexpectedValueException
	 */
	public function Connect(string $sName, string $sProvider) : AdapterInterface
	{
		Oauth2ClientLog::Info(__FUNCTION__, null, [$sName, $sProvider]);
		list($sProviderName, $aConfig) = ConfigService::GetInstance()->GetConfig($sName, $sProvider);
		Oauth2ClientLog::Info(__FUNCTION__, null, $aConfig);
		$oLogger = new Logger(Logger::DEBUG, APPROOT.'log/hybridauth.log');
		$oHybridAuth = new Hybridauth($aConfig, null, null, $oLogger);
		/** @var \Hybridauth\Storage\Session $aStorage */
		//$aStorage = $oHybridAuth->getAdapter($sProviderName)->getStorage();
		//$aTokenInfo = $oHybridAuth->getAdapter($sProviderName)->getStoredData('access_token');

		$oAdapter = $oHybridAuth->getAdapter($sProviderName);
		if ($oAdapter->isConnected()){
			//clear inside session
			$oAdapter->disconnect();

			// refresh tokens if needed
			$oAdapter->maintainToken();
			if ($oAdapter->hasAccessTokenExpired() === true) {
				$oAdapter->refreshAccessToken();
			}
		} else {
			//Oauth2ClientLog::Info("Connect aStorage", null, ['hybridauth_access_token' => $aTokenInfo]);
			$oHybridAuth->authenticate($sProviderName);
			//redirection to the IDP
		}
		return $oAdapter;
	}

	public function StoreTokens(string $sName, string $sProvider) : AdapterInterface
	{
		Oauth2ClientLog::Info(__FUNCTION__, null, [$sName, $sProvider]);
		list($sProviderName, $aConfig) = ConfigService::GetInstance()->GetConfig($sName, $sProvider);
		Oauth2ClientLog::Info(__FUNCTION__, null, $aConfig);
		$oLogger = new Logger(Logger::DEBUG, APPROOT.'log/hybridauth.log');
		$oHybridAuth = new Hybridauth($aConfig, null, null, $oLogger);
		$oAdapter = $oHybridAuth->authenticate($sProviderName);

		ConfigService::GetInstance()->SetTokens($sName, $sProvider, $oAdapter, $aConfig);

		Oauth2ClientLog::Info(__FUNCTION__, null, [$oAdapter->getUserProfile()]);
		return $oAdapter;
	}

}
