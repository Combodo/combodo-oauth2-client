<?php

namespace Combodo\iTop\Oauth2Client\Test\Integration;

use Combodo\iTop\Application\Helper\Session;
use Combodo\iTop\AuthentToken\Helper\TokenAuthHelper;
use Combodo\iTop\AuthentToken\Hook\TokenLoginExtension;
use Combodo\iTop\AuthentToken\Model\Oauth2UserApplication;
use Combodo\iTop\AuthentToken\Service\Oauth2ApplicationService;
use Combodo\iTop\Oauth2Client\Helper\Oauth2ClientLog;
use Combodo\iTop\Oauth2Client\Service\Oauth2Service;
use Combodo\iTop\Test\UnitTest\ItopDataTestCase;
use Config;
use Hybridauth\Adapter\FilterService;
use Hybridauth\Adapter\OAuth2;
use Hybridauth\Storage\StorageImpl;
use MetaModel;
use Oauth2Application;
use lnkOauth2ApplicationToUser;
use ItopOauth2Client;
use Oauth2Client;

class ItopIntegrationTest extends ItopDataTestCase
{
	const USE_TRANSACTION = false;

	private ?string $sToken;
	protected $sPassword = "Iuytrez9876543ç_è-(";
	protected $sLogin;
	protected $sConfigTmpBackupFile;
	protected $oUser;
	protected $sOrgName;
	protected $sOrgId;
	protected string $sUniqId;
	protected FilterService $oFilterService;

	protected function setUp(): void
	{
		parent::setUp();

		clearstatcache();
		$this->sConfigTmpBackupFile = tempnam(sys_get_temp_dir(), "config_");
		file_put_contents($this->sConfigTmpBackupFile, file_get_contents(MetaModel::GetConfig()->GetLoadedFile()));

		$sAuthorizePath = $this->GetAppRoot() . 'env-production/authent-token/authorize.php';
		if (! is_file($sAuthorizePath)){
			$this->markTestSkipped("oauth not available in iTop");
		}

		$this->RequireOnceItopFile('env-production/authent-token/vendor/autoload.php');
		$this->RequireOnceItopFile('env-production/combodo-oauth2-client/vendor/autoload.php');

		$this->sUniqId = uniqid();
		$this->sLogin = "rest-user-".$this->sUniqId;
		$this->sOrgName = "Org-$this->sUniqId";
		$this->sOrgId = $this->CreateOrganization($this->sOrgName)->GetKey();
		$this->oUser = $this->CreateContactlessUser($this->sLogin,
			ItopDataTestCase::$aURP_Profiles['Administrator'],
			$this->sPassword
		);

		@chmod(MetaModel::GetConfig()->GetLoadedFile(), 0770);
		$this->InitLoginMode(TokenLoginExtension::LOGIN_TYPE);

		MetaModel::GetConfig()->Set('log_level_min', [Oauth2ClientLog::CHANNEL_DEFAULT => 'Debug'], 'auth-token');
		MetaModel::GetConfig()->Set('secure_rest_services', true, 'auth-token');
		MetaModel::GetConfig()->Set('allow_rest_services_via_tokens', true, 'auth-token');
		MetaModel::GetConfig()->SetModuleSetting(TokenAuthHelper::MODULE_NAME, 'personal_tokens_allowed_profiles', ['Administrator', 'Service Desk Agent']);

		MetaModel::GetConfig()->WriteToFile();
		@chmod(MetaModel::GetConfig()->GetLoadedFile(), 0440);

		$this->oFilterService = $this->createMock(FilterService::class);
		OAuth2::setFilterService($this->oFilterService);
		$this->sToken = null;
	}

	protected function tearDown(): void
	{
		parent::tearDown();

		OAuth2::setFilterService(null);
		if (!is_null($this->sConfigTmpBackupFile) && is_file($this->sConfigTmpBackupFile)) {
			//put config back
			$sConfigPath = MetaModel::GetConfig()->GetLoadedFile();
			@chmod($sConfigPath, 0770);
			$oConfig = new Config($this->sConfigTmpBackupFile);
			$oConfig->WriteToFile($sConfigPath);
			@chmod($sConfigPath, 0440);
		}
	}

	protected function InitLoginMode($sLoginMode)
	{
		$aAllowedLoginTypes = MetaModel::GetConfig()->GetAllowedLoginTypes();
		if (!in_array($sLoginMode, $aAllowedLoginTypes)) {
			$aAllowedLoginTypes[] = $sLoginMode;
			MetaModel::GetConfig()->SetAllowedLoginTypes($aAllowedLoginTypes);
			$sConfigFile = APPROOT.'conf/'.\utils::GetCurrentEnvironment().'/config-itop.php';
			@chmod($sConfigFile, 0770); // Allow overwriting the file
			MetaModel::GetConfig()->WriteToFile();
		}
	}

	protected function CreateOauth2UserApplication(): Oauth2UserApplication
	{
		/** @var Oauth2Application $oOauth2Application */
		$oOauth2Application = $this->createObject(Oauth2Application::class, [
			'org_id'       => $this->sOrgId,
			"application"  => "test",
			"redirect_uri" => \utils::GetAbsoluteUrlAppRoot() . "env-production/combodo-oauth2-client/landing.php",
		]);

		/** @var lnkOauth2ApplicationToUser $oLnkOauth2ApplicationToUser */
		$oLnkOauth2ApplicationToUser = $this->createObject(lnkOauth2ApplicationToUser::class, [
			'application_id' => $oOauth2Application->GetKey(),
			'user_id'        => $this->oUser->GetKey(),
		]);

		return new Oauth2UserApplication($oOauth2Application, $oLnkOauth2ApplicationToUser);
	}

	public function CreateItopOauth2Client(array $aFields = []): ItopOauth2Client {
		$aCurrentFields = [
			'name' => 'itop_oauth_validation',
			"url" => \utils::GetAbsoluteUrlAppRoot(),
		];

		$aCurrentFields = array_merge($aCurrentFields, $aFields);

		/** @var ItopOauth2Client $oOauth2Client */
		$oOauth2Client = $this->createObject(ItopOauth2Client::class,
			$aCurrentFields
		);

		return $oOauth2Client;
	}

	public function testGetTokenByCodeAfterAuthorize()
	{
		$oExpectedOauth2UserApplication = $this->CreateOauth2UserApplication();
		$oOauth2Application = $oExpectedOauth2UserApplication->oOauth2Application;
		$sClientId = $oOauth2Application->Get('client_id');
		$sClientSecret = $oOauth2Application->Get('client_secret')->GetPassword();

		$oLnkOauth2ApplicationToUser = $oExpectedOauth2UserApplication->oLnkOauth2ApplicationToUser;
		$sAuthorizationState = "STATE-123";
		$sCode = Oauth2ApplicationService::GetInstance()->SaveCode($oLnkOauth2ApplicationToUser, $sAuthorizationState);
		$this->sToken = $oLnkOauth2ApplicationToUser->Get('access_token')->GetPassword();

		$aParams = [
			'client_id' => $sClientId,
			'client_secret' => $sClientSecret,
			'authorization_state' => $sAuthorizationState,
		];
		$oItopOauth2Client = $this->CreateItopOauth2Client($aParams);
		Oauth2Service::GetInstance()->InitByOauth2Client($oItopOauth2Client, null, new StorageImpl());

		$this->oFilterService->method('filter_input')
			->willReturnCallback(function ($type, $var_name, $filter, $options) use ($sCode, $sAuthorizationState) {
				if ($var_name === 'state'){
					return $sAuthorizationState;
				}
				if ($var_name === 'code'){
					return $sCode;
				}
				return null;
			});

		/*$_POST=[
			'state' => $sAuthorizationState,
			'code' => $sCode,
		];*/
		$_SERVER = ['REQUEST_METHOD' => 'POST'];

		$_SERVER['REMOTE_ADDR']="127.0.0.1";
		$this->assertEquals($this->sToken, Oauth2Service::GetInstance()->AuthenticateFinish());
	}

	public function testRefreshToken()
	{
		$oExpectedOauth2UserApplication = $this->CreateOauth2UserApplication();
		$oOauth2Application = $oExpectedOauth2UserApplication->oOauth2Application;
		$sClientId = $oOauth2Application->Get('client_id');
		$sClientSecret = $oOauth2Application->Get('client_secret')->GetPassword();

		$oLnkOauth2ApplicationToUser = $oExpectedOauth2UserApplication->oLnkOauth2ApplicationToUser;
		$sAuthorizationState = "STATE-123";
		Oauth2ApplicationService::GetInstance()->SaveCode($oLnkOauth2ApplicationToUser, $sAuthorizationState);

		$sOldAccessToken = $oLnkOauth2ApplicationToUser->Get('access_token')->GetPassword();
		$aParams = [
			'client_id' => $sClientId,
			'client_secret' => $sClientSecret,
			'authorization_state' => $sAuthorizationState,
			'refresh_token' => $oLnkOauth2ApplicationToUser->Get('refresh_token')->GetPassword(),
			'refresh_token_expiration' => $oLnkOauth2ApplicationToUser->Get('refresh_token_expiration'),
			'access_token' => $sOldAccessToken,
			'access_token_expiration' => date(\AttributeDateTime::GetSQLFormat(), time()-5),
		];
		$oItopOauth2Client = $this->CreateItopOauth2Client($aParams);
		Oauth2Service::GetInstance()->InitByOauth2Client($oItopOauth2Client, null, new StorageImpl());

		$_SERVER['REMOTE_ADDR']="127.0.0.1";
		$sNewAccessToken = Oauth2Service::GetInstance()->GetAccessToken();
		$this->assertNotEquals($sOldAccessToken, $sNewAccessToken);
		$this->assertNotNull($sNewAccessToken);
	}

	public function testGetUserApi()
	{
		$oExpectedOauth2UserApplication = $this->CreateOauth2UserApplication();
		$oOauth2Application = $oExpectedOauth2UserApplication->oOauth2Application;
		$sClientId = $oOauth2Application->Get('client_id');
		$sClientSecret = $oOauth2Application->Get('client_secret')->GetPassword();

		$this->updateObject(lnkOauth2ApplicationToUser::class, $oExpectedOauth2UserApplication->oLnkOauth2ApplicationToUser->GetKey(),
			[
				'scope' => TokenAuthHelper::TAG_OAUTH2_GETUSER_ENDPOINT,
			]
		);

		$oLnkOauth2ApplicationToUser = $oExpectedOauth2UserApplication->oLnkOauth2ApplicationToUser;
		$sAuthorizationState = "STATE-123";
		Oauth2ApplicationService::GetInstance()->SaveCode($oLnkOauth2ApplicationToUser, $sAuthorizationState);

		$aParams = [
			'client_id' => $sClientId,
			'client_secret' => $sClientSecret,
			'authorization_state' => $sAuthorizationState,
			'refresh_token' => $oLnkOauth2ApplicationToUser->Get('refresh_token')->GetPassword(),
			'refresh_token_expiration' => $oLnkOauth2ApplicationToUser->Get('refresh_token_expiration'),
			'access_token' => $oLnkOauth2ApplicationToUser->Get('access_token')->GetPassword(),
			'access_token_expiration' => $oLnkOauth2ApplicationToUser->Get('access_token_expiration'),
		];
		$oItopOauth2Client = $this->CreateItopOauth2Client($aParams);
		Oauth2Service::GetInstance()->InitByOauth2Client($oItopOauth2Client, null, new StorageImpl());

		$_SERVER['REMOTE_ADDR']="127.0.0.1";
		$oProfile = Oauth2Service::GetInstance()->GetUserProfile();
		$this->assertNotNull($oProfile);
		$this->assertEquals($this->sLogin, $oProfile->identifier, var_export($oProfile->data, true));
	}

	public function testOQLRestGetApi()
	{
		$oExpectedOauth2UserApplication = $this->CreateOauth2UserApplication();
		$oOauth2Application = $oExpectedOauth2UserApplication->oOauth2Application;
		$sClientId = $oOauth2Application->Get('client_id');
		$sClientSecret = $oOauth2Application->Get('client_secret')->GetPassword();

		$this->updateObject(lnkOauth2ApplicationToUser::class, $oExpectedOauth2UserApplication->oLnkOauth2ApplicationToUser->GetKey(),
			[
				'scope' => \ContextTag::TAG_REST,
			]
		);

		$oLnkOauth2ApplicationToUser = $oExpectedOauth2UserApplication->oLnkOauth2ApplicationToUser;
		$sAuthorizationState = "STATE-123";
		Oauth2ApplicationService::GetInstance()->SaveCode($oLnkOauth2ApplicationToUser, $sAuthorizationState);

		$aParams = [
			'client_id' => $sClientId,
			'client_secret' => $sClientSecret,
			'authorization_state' => $sAuthorizationState,
			'refresh_token' => $oLnkOauth2ApplicationToUser->Get('refresh_token')->GetPassword(),
			'refresh_token_expiration' => $oLnkOauth2ApplicationToUser->Get('refresh_token_expiration'),
			'access_token' => $oLnkOauth2ApplicationToUser->Get('access_token')->GetPassword(),
			'access_token_expiration' => $oLnkOauth2ApplicationToUser->Get('access_token_expiration'),
		];
		$oItopOauth2Client = $this->CreateItopOauth2Client($aParams);
		Oauth2Service::GetInstance()->InitByOauth2Client($oItopOauth2Client, null, new StorageImpl());

		$_SERVER['REMOTE_ADDR']="127.0.0.1";
		$sUrl = \utils::GetAbsoluteUrlAppRoot() . 'webservices/rest.php';

		$sJsonData = <<<JSON
		{
			"operation": "core/get",
		    "class": "User",
		    "key": "SELECT User",
		    "output_fields": "login",
		    "limit": "1",
		    "page": "1"
		}
JSON;

		$aRestParams = [
			'version' => '1.3',
			'json_data' => $sJsonData,
		];

		$oCollection = Oauth2Service::GetInstance()->ApiRequest($sUrl, 'GET', $aRestParams);
		$aRes = $oCollection->toArray();
		$this->assertEquals('0', $aRes['code']);
		$sMessage = $aRes['message'];
		$this->assertTrue(false !== strpos($sMessage, 'Found:'), "message should contain Found... $sMessage");
		$this->assertTrue(false === strpos($sMessage, 'Found: 0'), "at least one object found... $sMessage");
	}

	private function CallItopUrl($sUrl, ?array $aPostFields = null, $bIsPost=true)
	{
		$ch = curl_init();

		curl_setopt($ch, CURLOPT_URL, $sUrl);
		curl_setopt($ch, CURLOPT_POST, $bIsPost ? 1 : 0);// set post data to true
		curl_setopt($ch, CURLOPT_POSTFIELDS, $aPostFields);
		curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
		curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 0);
		curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, 0);
		curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
		$sOutput = curl_exec($ch);

		//echo "$sUrl curl_error:".curl_error($ch);
		//echo "$sUrl curl_errno:".curl_errno($ch);
		//echo curl_getinfo($ch, CURLINFO_EFFECTIVE_URL);
		//var_dump(curl_get($ch, CURLOPT_HEADER));

		curl_close($ch);

		return $sOutput;
	}
}
