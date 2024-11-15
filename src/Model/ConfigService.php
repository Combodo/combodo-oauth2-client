<?php
/**
 * @copyright   Copyright (C) 2010-2024 Combodo SARL
 * @license     http://opensource.org/licenses/AGPL-3.0
 */

namespace Combodo\iTop\Oauth2Client\Model;

use AttributeDateTime;
use Combodo\iTop\ItopAttributeEncryptedPassword\Model\ormEncryptedPassword;
use Combodo\iTop\Oauth2Client\Helper\Oauth2ClientException;
use Combodo\iTop\Oauth2Client\Helper\Oauth2ClientHelper;
use Combodo\iTop\Oauth2Client\Helper\Oauth2ClientLog;
use Hybridauth\Adapter\AdapterInterface;
use Oauth2Client;

class ConfigService
{
	/** @var ConfigService */
	private static $oInstance;

	private function __construct()
	{
		Oauth2ClientLog::Enable();
	}

	public static function GetInstance(): ConfigService
	{
		if (!isset(static::$oInstance)) {
			static::$oInstance = new ConfigService();
		}

		return static::$oInstance;
	}

	/**
	 * Get the configuration for a provider
	 *
	 * @param string $sName Name of the entry to get
	 * @param string $sProvider Generic name of the provider (Hybridauth\Provider\Github for example)
	 * @param bool $bResetTokens : reset tokens in DB before generating configuration
	 *
	 * @return array of parameters corresponding to the provider's configuration
	 * @throws \Combodo\iTop\Oauth2Client\Helper\Oauth2ClientException*
	 */
	public function GetConfig(string $sName, string $sProvider, bool $bResetTokens=false) : array
	{
		try {
			Oauth2ClientLog::Debug(__FUNCTION__, null, [$sName, $sProvider]);
			$oSearch = \DBSearch::FromOQL("SELECT Oauth2Client WHERE name=:name AND provider=:provider");
			$oSet = new \DBObjectSet($oSearch, [], ['name' => $sName, 'provider' => $sProvider]);
			if ($oSet->Count() != 1) {
				throw new Oauth2ClientException("Missing configuration", 0, null, ['name' => $sName, 'provider' => $sProvider]);
			}

			/** @var Oauth2Client $oOauth2Client */
			$oOauth2Client = $oSet->Fetch();

			if ($bResetTokens){
				$this->ResetTokens($oOauth2Client);
			}

			$aData = [
				'enabled' => $oOauth2Client->Get('status') === 'active',
				'keys' => [
					'id' => $oOauth2Client->Get('client_id'),
					'secret' => $oOauth2Client->Get('client_secret')->GetPassword(),
				],
				//'expires_in' => date_format(new \DateTime($oExpireAt), 'U') - time(),
				'callback' => $this->GetLandingURL($oOauth2Client),
				'debug_mode' => Oauth2ClientLog::GetHybridauthDebugMode(),
			];
			$aTokens = [];
			$aTokenFieldMapping = $oOauth2Client->GetAccessTokenModelToHybridauthMapping();
			foreach ($oOauth2Client->GetModelToHybridauthMapping() as $sHybridauthId => $siTopId) {
				$sVal = $oOauth2Client->Get($siTopId);
				if ($sVal instanceof ormEncryptedPassword) {
					$sVal = $sVal->GetPassword();
				}
				if (\utils::IsNotNullOrEmptyString($sVal)) {
					if (is_a(\MetaModel::GetAttributeDef(Oauth2Client::class, $siTopId), AttributeDateTime::class)) {
						$oDateTime = \DateTime::createFromFormat(AttributeDateTime::GetSQLFormat(), $sVal);
						$sVal = $oDateTime->getTimestamp();
					}

					if (array_key_exists($sHybridauthId, $aTokenFieldMapping)) {
						$aTokens[$sHybridauthId] = $sVal;
					} else {
						$aData[$sHybridauthId] = $sVal;
					}
				}
			}
			if (count($aTokens) > 0) {
				$aData['tokens'] = $aTokens;
			}
			$sProviderName = mb_strtolower($this->GetHybridauthProviderName($sProvider));
			$aConf = ['providers' => [$sProviderName => $aData]];
			Oauth2ClientLog::Debug(__FUNCTION__, null, ['name' => $sName, 'provider' => $sProvider, 'hybridauth_provider_name' => $sProviderName, 'aConf' => $aConf]);

			return [$sProviderName, $aConf];
		} catch (\Exception $e) {
			throw new Oauth2ClientException(__FUNCTION__.': failed', 0, $e);
		}
	}

	public function SetTokens(string $sName, string $sProvider, AdapterInterface $oAdapter, array $aConfig) : void
	{
		try {
			Oauth2ClientLog::Debug(__FUNCTION__, null, [$sName, $sProvider]);
			$oSearch = \DBSearch::FromOQL("SELECT Oauth2Client WHERE name=:name AND provider=:provider");
			$oSet = new \DBObjectSet($oSearch, [], ['name' => $sName, 'provider' => $sProvider]);
			if ($oSet->Count() != 1) {
				throw new Oauth2ClientException("Missing configuration", 0, null, ['name' => $sName, 'provider' => $sProvider]);
			}
			/** @var Oaut2Client $oOaut2Client */
			$oOaut2Client = $oSet->Fetch();
			$aTokens = $oAdapter->getAccessToken();
			Oauth2ClientLog::Info(__FUNCTION__, null, ['name' => $sName, 'provider' => $sProvider, 'aTokens' => $aTokens]);
			$aMapping = $oOaut2Client->GetAccessTokenModelToHybridauthMapping();
			$sScope = $aConfig['scope'] ?? '';
			if (\utils::IsNullOrEmptyString($sScope)) {
				/** @noinspection OneTimeUseVariablesInspection */
				$oClass = new \ReflectionClass($oAdapter);
				$oProperty = $oClass->getProperty('scope');
				$oProperty->setAccessible(true);
				$sScope = $oProperty->getValue($oAdapter);
				$oOaut2Client->Set('scope', $sScope);
				Oauth2ClientLog::Info(__FUNCTION__, null,
					[
						'name' => $sName,
						'provider' => $sProvider,
						'scope' => $sScope,
					]
				);
			}
			foreach ($aTokens as $sHybridauthKey => $sVal) {
				$siTopFieldCode = $aMapping[$sHybridauthKey] ?? '';
				Oauth2ClientLog::Info(__FUNCTION__, null,
					[
						'name' => $sName,
						'provider' => $sProvider,
						'sHybridauthKey' => $sHybridauthKey,
						'siTopFieldCode' => $siTopFieldCode,
						'sVal' => $sVal,
					]
				);

				if (\utils::IsNotNullOrEmptyString($siTopFieldCode)) {
					$oOaut2Client->Set($siTopFieldCode, $sVal);
				}
			}
			$oOaut2Client->DBWrite();
		} catch (\Exception $e) {
			throw new Oauth2ClientException(__FUNCTION__.': failed', 0, $e);
		}
	}

	/**
	 * @param \Oauth2Client $oOauth2Client
	 *
	 * @return void
	 */
	public function ResetTokens(Oauth2Client &$oOauth2Client) : void
	{
		$aMapping = $oOauth2Client->GetAccessTokenModelToHybridauthMapping();

		foreach ($aMapping as $sHybridauthKey => $siTopFieldCode){
			$oOauth2Client->Set($siTopFieldCode, '');
		}
		$oOauth2Client->DBWrite();
		$oOauth2Client->Reload();
	}

	/**
	 * Provide the access_token fields mapping between hybridauth and iTop model
	 * @return array
	 */
	public function GetAccessTokenModelToHybridauthMapping() : array {
		return [
			'access_token' => 'access_token',
			'access_token_secret' => 'access_token_secret',
			'token_type' => 'token_type',
			'refresh_token' => 'refresh_token',
			'expires_at' => 'access_token_expiration',
		];
	}

	/**
	 * Provide the mapping between hybridauth and iTop model
	 * @return array
	 */
	public function GetModelToHybridauthMapping() : array {
		return array_merge(['scope' => 'scope' ], $this->GetAccessTokenModelToHybridauthMapping());
	}

	private function GetClassName(string $sProvider) : string
	{
		$i = strrpos($sProvider, '\\');
		if ($i === false){
			return $sProvider;
		}

		return substr($sProvider, $i+1);
	}

	/**
	 * @param \Oauth2Client $oObj
	 *
	 * @return string
	 * @throws \Combodo\iTop\Oauth2Client\Helper\Oauth2ClientException
	 */
	public function GetLandingURL(Oauth2Client $oObj) : string
	{
		try {
			return \utils::GetAbsoluteUrlModulesRoot().Oauth2ClientHelper::MODULE_NAME."/landing.php";
		} catch (\Exception $e) {
			throw new Oauth2ClientException(__FUNCTION__.': failed', 0, $e);
		}
	}

	/**
	 * @param \Oauth2Client $oObj
	 *
	 * @return string
	 * @return bool
	 * @throws \Combodo\iTop\Oauth2Client\Helper\Oauth2ClientException
	 */
	public function GetConnectUrl(Oauth2Client $oObj, bool $bReset=false) : string
	{
		try {
			$sName = urlencode($oObj->Get('name'));
			$sProvider = urlencode(base64_encode($oObj->Get('provider')));

			$sUrl = \utils::GetAbsoluteUrlModulesRoot().Oauth2ClientHelper::MODULE_NAME."/connect.php?name=$sName&provider=$sProvider";
			if ($bReset){
				$sUrl .= "&reset_token=true";
			}

			return $sUrl;
		} catch (\Exception $e) {
			throw new Oauth2ClientException(__FUNCTION__.': failed', 0, $e);
		}
	}

	public function GetHybridauthProvider(Oauth2Client $oObj) : string
	{
		$sClassName = $this->GetClassName(get_class($oObj));
		$sProviderClassName = str_replace('Oauth2Client', '', $sClassName);
		return "Hybridauth\\Provider\\$sProviderClassName";
	}
}
