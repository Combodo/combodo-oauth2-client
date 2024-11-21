<?php

namespace Combodo\iTop\Oauth2Client\Model;

use AttributeDateTime;
use Combodo\iTop\ItopAttributeEncryptedPassword\Model\ormEncryptedPassword;
use Combodo\iTop\Oauth2Client\Helper\Oauth2ClientException;
use Combodo\iTop\Oauth2Client\Helper\Oauth2ClientHelper;
use Combodo\iTop\Oauth2Client\Helper\Oauth2ClientLog;
use DateTime;
use DBObjectSet;
use DBSearch;
use Exception;
use MetaModel;
use Oauth2Client;
use utils;

class Oauth2ClientService {
	private static Oauth2ClientService $oInstance;
	private string $sName;
	private string $sProvider;
	private Oauth2Client $oOauth2Client;

	protected function __construct() {
	}

	final public static function GetInstance(): Oauth2ClientService {
		if (!isset(static::$oInstance)) {
			static::$oInstance = new static();
		}

		return static::$oInstance;
	}

	final public static function SetInstance(?Oauth2ClientService $oInstance): void
	{
		static::$oInstance = $oInstance;
	}

	public function InitClient(string $sName, string $sProvider)
	{
		Oauth2ClientLog::Debug(__FUNCTION__, null, [$sName, $sProvider]);
		$this->sName = $sName;
		$this->sProvider = $sProvider;

		$this->GetOauth2Client();
	}

	public function GetOauth2Client() : Oauth2Client
	{
		try {
			if (isset($this->oOauth2Client)){
				return $this->oOauth2Client;
			}

			Oauth2ClientLog::Debug(__FUNCTION__, null, [$this->sName, $this->sProvider]);
			$oSearch = DBSearch::FromOQL("SELECT Oauth2Client WHERE name=:name AND provider=:provider");
			$oSet = new DBObjectSet($oSearch, [], ['name' => $this->sName, 'provider' => $this->sProvider]);
			if ($oSet->Count() != 1) {
				throw new Oauth2ClientException("Missing configuration", 0, null,
					['name' => $this->sName, 'provider' => $this->sProvider]);
			}

			/** @var Oauth2Client $oDBObject */
			$oDBObject = $oSet->Fetch();

			$this->oOauth2Client = $oDBObject;

			return $this->oOauth2Client;
		} catch (Exception $e) {
			throw new Oauth2ClientException(__FUNCTION__.': failed', 0, $e);
		}
	}

	public function GetAuthenticateConfiguration() : array
	{
		$aData = [
			'enabled' => $this->oOauth2Client->Get('status') === 'active',
			'keys' => [
				'id' => $this->oOauth2Client->Get('client_id'),
				'secret' => $this->oOauth2Client->Get('client_secret')->GetPassword(),
			],
			'adapter' => $this->oOauth2Client->Get('provider'),
			//'expires_in' => date_format(new \DateTime($oExpireAt), 'U') - time(),
			'callback' => Oauth2ClientHelper::GetLandingURL(),
			'debug_mode' => Oauth2ClientLog::GetHybridauthDebugMode(),
		];

		$sScope = $this->oOauth2Client->Get('scope');
		if (utils::IsNotNullOrEmptyString($sScope)) {
			$aData['scope'] = $sScope;
		}

		foreach ($this->oOauth2Client->GetModelToHybridauthMapping() as $sHybridauthId => $sAttCode) {
			$val = $this->oOauth2Client->Get($sAttCode);
			if ($val instanceof ormEncryptedPassword) {
				$val = $val->GetPassword();
			} else if (MetaModel::GetAttributeDef(get_class($this->oOauth2Client), $sAttCode) instanceof AttributeDateTime) {
				$oDateTime = DateTime::createFromFormat(AttributeDateTime::GetSQLFormat(), $val);
				$val = $oDateTime->getTimestamp();
			}

			if (utils::IsNotNullOrEmptyString($val)) {
				$aData[$sHybridauthId] = $val;
			}
		}

		$sProviderName = Oauth2ClientHelper::GetProviderName($this->sProvider);
		$aConf = ['providers' => [$sProviderName => $aData]];

		return $aConf;
	}

	public function GetRefreshTokenConfiguration() : array
	{
		$sProviderName = Oauth2ClientHelper::GetProviderName($this->sProvider);
		$aConf = $this->GetAuthenticateConfiguration();
		$aData = $aConf['providers'][$sProviderName];

		$aTokenMapping = $this->oOauth2Client->GetTokenModelToHybridauthMapping();
		$aTokens = [];
		foreach ($aTokenMapping as $sHybridauthId => $sAttCode) {
			$val = $this->oOauth2Client->Get($sAttCode);
			if ($val instanceof ormEncryptedPassword) {
				$val = $val->GetPassword();
			} else if (MetaModel::GetAttributeDef(get_class($this->oOauth2Client), $sAttCode) instanceof AttributeDateTime) {
				$oDateTime = DateTime::createFromFormat(AttributeDateTime::GetSQLFormat(), $val);
				$val = $oDateTime->getTimestamp();
			}

			if (utils::IsNotNullOrEmptyString($val)) {
				$aTokens[$sHybridauthId] = $val;
			}
		}

		if (count($aTokens) > 0) {
			$aData['tokens'] = $aTokens;
		}
		$aConf = ['providers' => [$sProviderName => $aData]];
		$aConf['authorization_state'] = $this->oOauth2Client->Get('authorization_state');
		return $aConf;
	}

	public function SaveTokens(array $aTokenResponse) : void
	{
		Oauth2ClientLog::Debug(__FUNCTION__, null, $aTokenResponse);
		$aTokenMapping = $this->oOauth2Client->GetTokenModelToHybridauthMapping();
		foreach ($aTokenMapping as $sHybridauthId => $sAttCode) {
			$this->oOauth2Client->Set($sAttCode, $aTokenResponse[$sHybridauthId]);
		}

		$this->oOauth2Client->Set('authorization_state', $aTokenResponse['authorization_state'] ?? '');
		$this->oOauth2Client->DBWrite();
	}

	public function GetAccessToken() : ?string
	{
		$oAccessToken = $this->oOauth2Client->Get('access_token');
		if (is_null($oAccessToken)){
			return null;
		}
		return $oAccessToken->GetPassword();
	}

	public function IsExpired() : bool
	{
		$oAttDateTime = $this->oOauth2Client->Get('access_token_expiration');
		$oDateTime = DateTime::createFromFormat(AttributeDateTime::GetSQLFormat(), $oAttDateTime);
		return $oDateTime < new DateTime();
	}

	public function GetHybridauthProvider(Oauth2Client $oObj): string
	{
		$sClassName = Oauth2ClientHelper::GetClassName(get_class($oObj));
		$sProviderClassName = str_replace('Oauth2Client', '', $sClassName);

		return "Hybridauth\\Provider\\$sProviderClassName";
	}
}
