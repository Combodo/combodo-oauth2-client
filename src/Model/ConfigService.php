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
use Combodo\iTop\Oauth2Client\Service\HybridAuthService;
use DateTime;
use DBObjectSet;
use DBSearch;
use Exception;
use MetaModel;
use Oauth2Client;
use ReflectionClass;
use utils;

class ConfigService
{
	/** @var ?ConfigService */
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

	public static function SetInstance(?ConfigService $oInstance): void
	{
		static::$oInstance = $oInstance;
	}

	public function SetTokens(Oauth2Client $oOauth2Client): void
	{
		try {
			$sName = $oOauth2Client->Get('name');
			$sProvider = $oOauth2Client->Get('provider');

			Oauth2ClientLog::Debug(__FUNCTION__, null, [$sName, $sProvider]);
			$oOauth2 = $oOauth2Client->GetOauth2();
			$aTokens = $oOauth2->getAccessToken();
			Oauth2ClientLog::Debug(__FUNCTION__, null, ['name' => $sName, 'provider' => $sProvider, 'aTokens' => $aTokens]);
			$aMapping = $oOauth2Client->GetAccessTokenModelToHybridauthMapping();
			if (utils::IsNullOrEmptyString($oOauth2Client->Get('scope'))) {
				/** @noinspection OneTimeUseVariablesInspection */
				$oClass = new ReflectionClass($oOauth2);
				$oProperty = $oClass->getProperty('scope');
				$oProperty->setAccessible(true);
				$sScope = $oProperty->getValue($oOauth2);
				$oOauth2Client->Set('scope', $sScope);
				Oauth2ClientLog::Debug(__FUNCTION__, null,
					[
						'name' => $sName,
						'provider' => $sProvider,
						'scope' => $sScope,
					]
				);
			}
			foreach ($aTokens as $sHybridauthKey => $sVal) {
				$siTopFieldCode = $aMapping[$sHybridauthKey] ?? '';
				Oauth2ClientLog::Debug(__FUNCTION__, null,
					[
						'name' => $sName,
						'provider' => $sProvider,
						'sHybridauthKey' => $sHybridauthKey,
						'siTopFieldCode' => $siTopFieldCode,
						'sVal' => $sVal,
					]
				);

				if (utils::IsNotNullOrEmptyString($siTopFieldCode)) {
					$oOauth2Client->Set($siTopFieldCode, $sVal);
				}
			}
			$oOauth2Client->DBWrite();
		} catch (Exception $e) {
			throw new Oauth2ClientException(__FUNCTION__.': failed', 0, $e);
		}
	}

	/**
	 * @param \Oauth2Client $oOauth2Client : object is reloaded afterwhile
	 *
	 * @return void
	 */
	public function ResetTokens(Oauth2Client &$oOauth2Client): void
	{
		$aMapping = $oOauth2Client->GetAccessTokenModelToHybridauthMapping();

		foreach ($aMapping as $sHybridauthKey => $siTopFieldCode) {
			$oOauth2Client->Set($siTopFieldCode, '');
		}
		$oOauth2Client->DBWrite();
		$oOauth2Client->Reload();
	}

	/**
	 * Provide the access_token fields mapping between hybridauth and iTop model
	 *
	 * @return array
	 */
	public function GetAccessTokenModelToHybridauthMapping(): array
	{
		return [
			'access_token' => 'access_token',
			'token_type' => 'token_type',
			'refresh_token' => 'refresh_token',
			'expires_at' => 'access_token_expiration',
		];
	}

	/**
	 * Provide the mapping between hybridauth and iTop model
	 *
	 * @return array
	 */
	public function GetModelToHybridauthMapping(): array
	{
		return array_merge(['scope' => 'scope'], $this->GetAccessTokenModelToHybridauthMapping());
	}

	private function GetClassName(string $sProvider): string
	{
		$i = strrpos($sProvider, '\\');
		if ($i === false) {
			return $sProvider;
		}

		return substr($sProvider, $i + 1);
	}

	/**
	 * @return string
	 * @throws \Combodo\iTop\Oauth2Client\Helper\Oauth2ClientException
	 */
	public function GetLandingURL(): string
	{
		try {
			return utils::GetAbsoluteUrlModulesRoot().Oauth2ClientHelper::MODULE_NAME."/landing.php";
		} catch (Exception $e) {
			throw new Oauth2ClientException(__FUNCTION__.': failed', 0, $e);
		}
	}

	/**
	 * @param \Oauth2Client $oObj
	 * @param string $sAction
	 *
	 * @return string
	 * @throws \Combodo\iTop\Oauth2Client\Helper\Oauth2ClientException
	 */
	public function GetConnectUrl(Oauth2Client $oObj, string $sAction): string
	{
		try {
			$sName = urlencode($oObj->Get('name'));
			$sProvider = urlencode(base64_encode($oObj->Get('provider')));

			$sUrl = utils::GetAbsoluteUrlModulesRoot().Oauth2ClientHelper::MODULE_NAME."/connect.php?name=$sName&provider=$sProvider&action=$sAction";

			return $sUrl;
		} catch (Exception $e) {
			throw new Oauth2ClientException(__FUNCTION__.': failed', 0, $e);
		}
	}

	public function GetHybridauthProvider(Oauth2Client $oObj): string
	{
		$sClassName = $this->GetClassName(get_class($oObj));
		$sProviderClassName = str_replace('Oauth2Client', '', $sClassName);

		return "Hybridauth\\Provider\\$sProviderClassName";
	}


	/**
	 * Get the configuration for a provider
	 *
	 * @param string $sName Name of the entry to get
	 * @param string $sProvider Generic name of the provider (Hybridauth\Provider\Github for example)
	 * @param bool $bResetTokens : reset tokens in DB before generating configuration
	 *
	 * @return Oauth2Client
	 * @throws \Combodo\iTop\Oauth2Client\Helper\Oauth2ClientException*
	 */
	public function GetOauth2Client(string $sName, string $sProvider, bool $bResetTokens = false): Oauth2Client
	{
		try {
			Oauth2ClientLog::Debug(__FUNCTION__, null, [$sName, $sProvider]);
			$oSearch = DBSearch::FromOQL("SELECT Oauth2Client WHERE name=:name AND provider=:provider");
			$oSet = new DBObjectSet($oSearch, [], ['name' => $sName, 'provider' => $sProvider]);
			if ($oSet->Count() != 1) {
				throw new Oauth2ClientException("Missing configuration", 0, null, ['name' => $sName, 'provider' => $sProvider]);
			}

			/** @var Oauth2Client $oOauth2Client */
			$oOauth2Client = $oSet->Fetch();

			if ($bResetTokens) {
				$this->ResetTokens($oOauth2Client);
			}

			$aData = [
				'enabled' => $oOauth2Client->Get('status') === 'active',
				'keys' => [
					'id' => $oOauth2Client->Get('client_id'),
					'secret' => $oOauth2Client->Get('client_secret')->GetPassword(),
				],
				//'expires_in' => date_format(new \DateTime($oExpireAt), 'U') - time(),
				'callback' => $this->GetLandingURL(),
				'debug_mode' => Oauth2ClientLog::GetHybridauthDebugMode(),
			];
			$aTokens = [];
			$aTokenFieldMapping = $oOauth2Client->GetAccessTokenModelToHybridauthMapping();
			foreach ($oOauth2Client->GetModelToHybridauthMapping() as $sHybridauthId => $siTopId) {
				$sVal = $oOauth2Client->Get($siTopId);
				if ($sVal instanceof ormEncryptedPassword) {
					$sVal = $sVal->GetPassword();
				}
				if (utils::IsNotNullOrEmptyString($sVal)) {
					if (is_a(MetaModel::GetAttributeDef(get_class($oOauth2Client), $siTopId), AttributeDateTime::class)) {
						$oDateTime = DateTime::createFromFormat(AttributeDateTime::GetSQLFormat(), $sVal);
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
			$sProviderName = mb_strtolower($this->GetClassName($sProvider));
			$aConf = ['providers' => [$sProviderName => $aData]];
			Oauth2ClientLog::Debug(__FUNCTION__, null, ['name' => $sName, 'provider' => $sProvider, 'hybridauth_provider_name' => $sProviderName, 'aConf' => $aConf]);

			$oAuth2 = HybridAuthService::GetInstance()->GetOauth2($aConf, $sProviderName);
			$oOauth2Client->SetOauth2($oAuth2);

			return $oOauth2Client;
		} catch (Exception $e) {
			throw new Oauth2ClientException(__FUNCTION__.': failed', 0, $e);
		}
	}

}
