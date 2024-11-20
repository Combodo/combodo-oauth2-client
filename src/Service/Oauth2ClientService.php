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
use Hybridauth\Adapter\OAuth2;
use IssueLog;
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
	 * @return string: access token
	 * @throws \Combodo\iTop\Oauth2Client\Helper\Oauth2ClientException
	 */
	public function Connect(string $sName, string $sProvider, bool $bResetToken): string
	{
		try {
			Oauth2ClientLog::Debug(__FUNCTION__, null, [$sName, $sProvider]);
			$oOauth2Client = ConfigService::GetInstance()->GetOauth2Client($sName, $sProvider, $bResetToken);

			/** @var \Hybridauth\Adapter\OAuth2 $oOAuth2 */
			$oOAuth2 = $oOauth2Client->GetOauth2();
			if ($bResetToken){
				$oOAuth2->disconnect();
			}

			if (!$oOAuth2->isConnected()) {
				$oOAuth2->authenticate();
			}

			//refresh token if needed
			return $this->GetToken($oOauth2Client);
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
	 * @return OAuth2
	 * @throws \Combodo\iTop\Oauth2Client\Helper\Oauth2ClientException
	 */
	public function StoreTokens(string $sName, string $sProvider): Oauth2
	{
		try {
			Oauth2ClientLog::Debug(__FUNCTION__, null, [$sName, $sProvider]);
			$oOauth2Client = ConfigService::GetInstance()->GetOauth2Client($sName, $sProvider);
			$oOAuth2 = $oOauth2Client->GetOauth2();
			$oOAuth2->authenticate();
			ConfigService::GetInstance()->SetTokens($oOauth2Client);

			return $oOAuth2;
		} catch (Oauth2ClientException $e) {
			throw $e;
		} catch (Exception $e) {
			throw new Oauth2ClientException(__FUNCTION__.': failed', 0, $e);
		}
	}

	/**
	 * Get up to date token.
	 * Note: if needed, refresh workflow is triggered first. in that case its data are actualized (ie token expiration date...)
	 *
	 * @param \Oauth2Client $oOauth2Client
	 *
	 * @return string: access token
	 * @throws \Combodo\iTop\Oauth2Client\Helper\Oauth2ClientException
	 */
	public function GetToken(Oauth2Client $oOauth2Client): string
	{
		try {
			$sName = $oOauth2Client->Get('name');
			$sProvider = $oOauth2Client->Get('provider');

			$oOauth2ClientBisWithHybridauthOauth2Inside = ConfigService::GetInstance()->GetOauth2Client($sName, $sProvider);
			$oAuth2 = $oOauth2ClientBisWithHybridauthOauth2Inside->GetOauth2();
			if (!$oAuth2->isConnected()) {
				throw new Oauth2ClientException(__FUNCTION__.": Oauth2 not initialized");
			}

			// refresh tokens if needed
			$oAuth2->maintainToken();
			if ($oAuth2->hasAccessTokenExpired() === true) {
				Oauth2ClientLog::Debug(__FUNCTION__, null, ['hasAccessTokenExpired' => true]);
				$sRefreshResponse = $oAuth2->refreshAccessToken();
				Oauth2ClientLog::Debug(__FUNCTION__, null, [$sName, $sProvider, 'sRefreshResponse' => $sRefreshResponse]);

				ConfigService::GetInstance()->SetTokens($oOauth2ClientBisWithHybridauthOauth2Inside);
				$oOauth2Client->Reload();
			}

			return $oOauth2Client->Get('access_token')->GetPassword();
		} catch (Oauth2ClientException $e) {
			throw $e;
		} catch (Exception $e) {
			throw new Oauth2ClientException(__FUNCTION__.': failed', 0, $e);
		}
	}
}
