<?php
/**
 * @copyright   Copyright (C) 2010-2024 Combodo SARL
 * @license     http://opensource.org/licenses/AGPL-3.0
 */

namespace Combodo\iTop\Oauth2Client\Model;

use Combodo\iTop\Oauth2Client\Helper\Oauth2ClientException;
use Combodo\iTop\Oauth2Client\Helper\Oauth2ClientHelper;
use Combodo\iTop\Oauth2Client\Helper\Oauth2ClientLog;
use Hybridauth\Adapter\AdapterInterface;
use Hybridauth\Logger\Logger;
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

	public function GetConfig(string $sName, string $sProvider) : array
	{
		Oauth2ClientLog::Debug(__FUNCTION__, null, [$sName, $sProvider]);
		$oSearch = \DBSearch::FromOQL("SELECT Oauth2Client WHERE name=:name AND provider=:provider");
		$oSet = new \DBObjectSet($oSearch, [], ['name' => $sName, 'provider' => $sProvider]);
		if ($oSet->Count() != 1){
			throw new Oauth2ClientException("Missing configuration", 0, null, ['name' => $sName, 'provider' => $sProvider]);
		}

		//$aData = $oSet->FetchAssoc();
		//$aData['adapter'] = $sProvider;
		$oOaut2Client = $oSet->Fetch();
		$aData = [
			'enabled' => $oOaut2Client->Get('status') === 'active',
			'keys' => [
				'id' => $oOaut2Client->Get('client_id'),
				'secret' => $oOaut2Client->Get('client_secret'),
			],
			//'expires_in' => date_format(new \DateTime($oExpireAt), 'U') - time(),
			'callback' => \utils::GetAbsoluteUrlModulesRoot().Oauth2ClientHelper::MODULE_NAME.'/landing.php',
			'debug_mode' => Oauth2ClientLog::GetHybridauthDebugMode(),
		];

		$aTokens = [];
		$aTokenFieldMapping = $oOaut2Client->GetAccessTokenModelToHybridauthMapping();
		foreach ($oOaut2Client->GetModelToHybridauthMapping() as $sHybridauthId => $siTopId){
			$sVal = $oOaut2Client->Get($siTopId);
			if (\utils::IsNotNullOrEmptyString($sVal)){
				if (array_key_exists($sHybridauthId, $aTokenFieldMapping)){
					$aTokens[$sHybridauthId] = $sVal;
				} else {
					$aData[$sHybridauthId] = $sVal;
				}
			}
		}

		if (count($aTokens) > 0){
			$aData['tokens'] = $aTokens;
		}

		$sProviderName = mb_strtolower($this->GetHybridauthProviderName($sProvider));

		$aConf = [ 'providers' => [ $sProviderName => $aData ] ];

		Oauth2ClientLog::Debug(__FUNCTION__, null, ['name' => $sName, 'provider' => $sProvider, 'hybridauth_provider_name' => $sProviderName, 'aConf' => $aConf ]);
		return [ $sProviderName, $aConf ];
	}

	public function SetTokens(string $sName, string $sProvider, AdapterInterface $oAdapter, array $aConfig) : void
	{
		Oauth2ClientLog::Debug(__FUNCTION__, null, [$sName, $sProvider]);
		$oSearch = \DBSearch::FromOQL("SELECT Oauth2Client WHERE name=:name AND provider=:provider");
		$oSet = new \DBObjectSet($oSearch, [], ['name' => $sName, 'provider' => $sProvider]);
		if ($oSet->Count() != 1){
			throw new Oauth2ClientException("Missing configuration", 0, null, ['name' => $sName, 'provider' => $sProvider]);
		}

		$oOaut2Client = $oSet->Fetch();
		$aTokens = $oAdapter->getAccessToken();
		Oauth2ClientLog::Info(__FUNCTION__, null, ['name' => $sName, 'provider' => $sProvider, 'aTokens' => $aTokens ]);
		$aMapping = $oOaut2Client->GetModelToHybridauthMapping();

		$sScope = $aConfig['scope'] ?? '';
		if (\utils::IsNullOrEmptyString($sScope)){
			/** @noinspection OneTimeUseVariablesInspection */
			$oClass = new \ReflectionClass($oAdapter);
			$oProperty = $oClass->getProperty('scope');
			$oProperty->setAccessible(true);
			$sScope = $oProperty->getValue($oAdapter);
			$oOaut2Client->Set('scope', $sScope);
			Oauth2ClientLog::Info(__FUNCTION__, null, ['name' => $sName, 'provider' => $sProvider, 'scope' => $sScope, 'oClass' => var_export($oAdapter , true)]);
		}

		foreach ($aTokens as $sHybridauthKey => $sVal){
			$siTopFieldCode = $aMapping[$sHybridauthKey] ?? '';
			if (\utils::IsNotNullOrEmptyString($siTopFieldCode)){
				$oOaut2Client->Set($siTopFieldCode, $sVal);
			}
		}
		$oOaut2Client->DBWrite();
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

	public function GetHybridauthProviderName(string $sProvider) : string
	{
		$i = strrpos($sProvider, '\\');
		if ($i === false){
			return $sProvider;
		}

		return substr($sProvider, $i+1);
	}

	public function GetLandingURL(Oauth2Client $oObj) : string
	{
		$sName = urlencode($oObj->Get('name'));
		$sProvider = urlencode(base64_encode($oObj->Get('provider')));
		return \utils::GetAbsoluteUrlModulesRoot() . Oauth2ClientHelper::MODULE_NAME."/landing.php";
	}

	public function GetConnectUrl(Oauth2Client $oObj) : string
	{
		$sName = urlencode($oObj->Get('name'));
		$sProvider = urlencode(base64_encode($oObj->Get('provider')));
		return \utils::GetAbsoluteUrlModulesRoot() . Oauth2ClientHelper::MODULE_NAME."/connect.php?name=$sName&provider=$sProvider";
	}
}