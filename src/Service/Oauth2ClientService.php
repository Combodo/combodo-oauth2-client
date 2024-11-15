<?php
/**
 * @copyright   Copyright (C) 2010-2024 Combodo SARL
 * @license     http://opensource.org/licenses/AGPL-3.0
 */

namespace Combodo\iTop\Oauth2Client\Service;

use Combodo\iTop\Oauth2Client\Helper\Oauth2ClientException;
use Combodo\iTop\Oauth2Client\Helper\Oauth2ClientLog;
use Combodo\iTop\Oauth2Client\Model\ConfigService;
use Exception;
use Hybridauth\Adapter\AdapterInterface;
use Hybridauth\Hybridauth;
use Hybridauth\Logger\Logger;
use Oauth2Client;

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
	 * @param bool $bResetToken
	 *
	 * @return \Hybridauth\Adapter\AdapterInterface: when already connected returns the object. otherwise redirection occurs to IDP
	 * @throws \Combodo\iTop\Oauth2Client\Helper\Oauth2ClientException
	 */
	public function Connect(string $sName, string $sProvider, bool $bResetToken): AdapterInterface
	{

		try {
			Oauth2ClientLog::Debug(__FUNCTION__, null, [$sName, $sProvider]);
			[$sProviderName, $aConfig] = ConfigService::GetInstance()->GetConfig($sName, $sProvider, $bResetToken);
			$oHybridAuth = $this->GetHybridauth($aConfig);
			/** @var \Hybridauth\Storage\Session $aStorage */
			$oAdapter = $oHybridAuth->getAdapter($sProviderName);
			if ($oAdapter->isConnected()) {
				//clear inside session
				$oAdapter->disconnect();
			}
			$oHybridAuth->authenticate($sProviderName);

			return $oAdapter;
		} catch (Oauth2ClientException $e) {
			throw $e;
		} catch (Exception $e) {
			throw new Oauth2ClientException(__FUNCTION__.': failed', 0, $e);
		}
	}

	/**
	 * @param string $sName
	 * @param string $sProvider
	 *
	 * @return \Hybridauth\Adapter\AdapterInterface
	 * @throws \Combodo\iTop\Oauth2Client\Helper\Oauth2ClientException
	 */
	public function StoreTokens(string $sName, string $sProvider): AdapterInterface
	{
		try {
			Oauth2ClientLog::Debug(__FUNCTION__, null, [$sName, $sProvider]);
			[$sProviderName, $aConfig] = ConfigService::GetInstance()->GetConfig($sName, $sProvider);
			$oHybridAuth = $this->GetHybridauth($aConfig);
			$oAdapter = $oHybridAuth->authenticate($sProviderName);
			ConfigService::GetInstance()->SetTokens($sName, $sProvider, $oAdapter, $aConfig);

			return $oAdapter;
		} catch (Oauth2ClientException $e) {
			throw $e;
		} catch (Exception $e) {
			throw new Oauth2ClientException(__FUNCTION__.': failed', 0, $e);
		}
	}

	/**
	 * Get up to date token.if needed, refresh workflow is triggered first.
	 * @param \Oauth2Client $oOauth2Client: object is reloaded afterwhile
	 *
	 * @return string
	 * @throws \Combodo\iTop\Oauth2Client\Helper\Oauth2ClientException
	 */
	public function GetToken(Oauth2Client &$oOauth2Client): string
	{
		try {
			$sName = $oOauth2Client->Get('name');
			$sProvider = $oOauth2Client->Get('provider');
			[$sProviderName, $aConfig] = ConfigService::GetInstance()->GetConfig($sName, $sProvider);
			$oHybridAuth = $this->GetHybridauth($aConfig);
			/** @var \Hybridauth\Storage\Session $aStorage */
			$oAdapter = $oHybridAuth->getAdapter($sProviderName);
			if (!$oAdapter->isConnected()) {
				throw new Oauth2ClientException(__FUNCTION__.": Oauth not initialized");
			}

			// refresh tokens if needed
			$oAdapter->maintainToken();
			if ($oAdapter->hasAccessTokenExpired() === true) {
				Oauth2ClientLog::Debug(__FUNCTION__, null, ['hasAccessTokenExpired' => true]);
				$oAdapter->refreshAccessToken();
				ConfigService::GetInstance()->SetTokens($sName, $sProvider, $oAdapter, $aConfig);
				$oOauth2Client->Reload();
			}

			return $oOauth2Client->Get('access_token')->GetPassword();
		} catch (Oauth2ClientException $e) {
			throw $e;
		} catch (Exception $e) {
			throw new Oauth2ClientException(__FUNCTION__.': failed', 0, $e);
		}
	}

	/**
	 * @param array $aConfig
	 *
	 * @return \Hybridauth\Hybridauth
	 * @throws \Combodo\iTop\Oauth2Client\Helper\Oauth2ClientException
	 */
	private function GetHybridauth(array $aConfig): Hybridauth
	{
		try {
			Oauth2ClientLog::Debug(__FUNCTION__, null, $aConfig);
			$oLogger = new Logger(Oauth2ClientLog::GetHybridauthDebugMode(), APPROOT.'log/hybridauth.log');

			return new Hybridauth($aConfig, null, null, $oLogger);
		} catch (Exception $e) {
			throw new Oauth2ClientException(__FUNCTION__.': failed', 0, $e);
		}
	}
}
