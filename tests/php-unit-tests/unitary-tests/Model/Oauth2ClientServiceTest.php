<?php

namespace Combodo\iTop\Oauth2Client\Test\Model;
use Combodo\iTop\Oauth2Client\Helper\Oauth2ClientException;
use Combodo\iTop\Oauth2Client\Helper\Oauth2ClientHelper;
use Combodo\iTop\Oauth2Client\Helper\Oauth2ClientLog;
use Combodo\iTop\Oauth2Client\Model\Oauth2ClientService;
use Combodo\iTop\Test\UnitTest\ItopDataTestCase;
use Oauth2Client;

class Oauth2ClientServiceTest extends ItopDataTestCase {
	protected function setUp(): void {
		parent::setUp();
		$this->RequireOnceItopFile('env-production/combodo-oauth2-client/vendor/autoload.php');
	}

	protected function tearDown(): void {
		parent::tearDown();
	}

	public function CreateOauth2Client(string $sClassName = \GitHubOauth2Client::class, array $aFields = []): Oauth2Client {
		$aCurrentFields = [
			'name' => 'webhook',
			'client_id' => 'client_123',
			'client_secret' => 'secret456',
		];

		$aCurrentFields = array_merge($aCurrentFields, $aFields);

		/** @var \Oauth2Client $oOauth2Client */
		$oOauth2Client = $this->createObject($sClassName,
			$aCurrentFields
		);

		return $oOauth2Client;
	}

	public function CreateOauth2ClientWithTokens(string $sClassName = \GitHubOauth2Client::class, array $aFields = []): Oauth2Client {
		$aCurrentFields = [
			'access_token' => 'access_token1',
			'authorization_state' => 'HA-JYXSNR41K0D8BQHMGAOU6LI2C7TZP9FE5W3V',
			'token_type' => 'token_type1',
			'refresh_token' => 'refresh_token1',
			'access_token_expiration' => '2024-11-13 00:37:48',
		];

		$aCurrentFields = array_merge($aCurrentFields, $aFields);

		return $this->CreateOauth2Client($sClassName, $aCurrentFields);
	}

	public function testGetHybridauthProvider() {
		$oObj = $this->CreateOauth2Client();
		$this->assertEquals("Hybridauth\\Provider\\GitHub", Oauth2ClientService::GetHybridauthProvider($oObj));
	}

	public function testInitClient() {
		$oObj = $this->CreateOauth2Client();
		Oauth2ClientService::GetInstance()->InitClient($oObj->Get('name'), $oObj->Get('provider'));

		$oInitiatedOauth2Client = $this->InvokeNonPublicMethod(Oauth2ClientService::class, 'GetOauth2Client',
			Oauth2ClientService::GetInstance());
		$this->assertEquals($oObj->GetKey(), $oInitiatedOauth2Client->GetKey());
	}

	public function testInitClientByOauth2Client() {
		$oObj = $this->CreateOauth2Client();
		Oauth2ClientService::GetInstance()->InitClientByOauth2Client($oObj);

		$oInitiatedOauth2Client = $this->InvokeNonPublicMethod(Oauth2ClientService::class, 'GetOauth2Client',
			Oauth2ClientService::GetInstance());
		$this->assertEquals($oObj->GetKey(), $oInitiatedOauth2Client->GetKey());
	}

	public function testGetAuthenticateConfigurationWithoutScopeFilledIn() {
		$oObj = $this->CreateOauth2Client();
		Oauth2ClientService::GetInstance()->InitClient($oObj->Get('name'), $oObj->Get('provider'));

		$aExpected = [
			'providers' => [
				'github' => [
					'enabled' => true,
					'keys' => [
						'id' => 'client_123',
						'secret' => 'secret456',
					],
					'adapter' => 'Hybridauth\\Provider\\GitHub',
					'callback' => Oauth2ClientHelper::GetLandingURL(),
					'debug_mode' => Oauth2ClientLog::GetHybridauthDebugMode(),
				],
			],
		];
		$this->assertEquals($aExpected, Oauth2ClientService::GetInstance()->GetAuthenticateConfiguration());
	}

	public function testGetAuthenticateConfigurationWithScope() {
		$oObj = $this->CreateOauth2Client(\GoogleOauth2Client::class, ['scope' => 'scope789']);
		Oauth2ClientService::GetInstance()->InitClient($oObj->Get('name'), $oObj->Get('provider'));

		$aExpected = [
			'providers' => [
				'google' => [
					'enabled' => true,
					'keys' => [
						'id' => 'client_123',
						'secret' => 'secret456',
					],
					'adapter' => 'Hybridauth\\Provider\\Google',
					'callback' => Oauth2ClientHelper::GetLandingURL(),
					'debug_mode' => Oauth2ClientLog::GetHybridauthDebugMode(),
					'scope' => 'scope789',
				],
			],
		];
		$this->assertEquals($aExpected, Oauth2ClientService::GetInstance()->GetAuthenticateConfiguration());
	}

	public function testGetAuthenticateConfigurationWithAdditionalCustomMappingField_MSGraph_Tenant() {
		$oObj = $this->CreateOauth2Client(\MicrosoftGraphOauth2Client::class, ['tenant' => 'tenant321']);
		Oauth2ClientService::GetInstance()->InitClient($oObj->Get('name'), $oObj->Get('provider'));

		$aExpected = [
			'providers' => [
				'microsoftgraph' => [
					'enabled' => true,
					'keys' => [
						'id' => 'client_123',
						'secret' => 'secret456',
					],
					'adapter' => 'Hybridauth\\Provider\\MicrosoftGraph',
					'callback' => Oauth2ClientHelper::GetLandingURL(),
					'debug_mode' => Oauth2ClientLog::GetHybridauthDebugMode(),
					'tenant' => 'tenant321',
				],
			],
		];
		$this->assertEquals($aExpected, Oauth2ClientService::GetInstance()->GetAuthenticateConfiguration());
	}

	public function testGetRefreshTokenConfiguration_NoTokenSetYet() {
		$oObj = $this->CreateOauth2Client(\GoogleOauth2Client::class, ['scope' => 'scope789']);
		Oauth2ClientService::GetInstance()->InitClient($oObj->Get('name'), $oObj->Get('provider'));

		$aExpected = [
			'providers' => [
				'google' => [
					'enabled' => true,
					'keys' => [
						'id' => 'client_123',
						'secret' => 'secret456',
					],
					'adapter' => 'Hybridauth\\Provider\\Google',
					'callback' => Oauth2ClientHelper::GetLandingURL(),
					'debug_mode' => Oauth2ClientLog::GetHybridauthDebugMode(),
					'scope' => 'scope789',
				],
			],
			'authorization_state' => '',
		];
		$this->assertEquals($aExpected, Oauth2ClientService::GetInstance()->GetRefreshTokenConfiguration());
	}

	public function testGetRefreshTokenConfiguration_nominalcase() {
		$oObj = $this->CreateOauth2ClientWithTokens(\GitHubOauth2Client::class, ['scope' => 'scope789']);
		Oauth2ClientService::GetInstance()->InitClient($oObj->Get('name'), $oObj->Get('provider'));

		$aExpected = [
			'providers' => [
				'github' => [
					'enabled' => true,
					'keys' => [
						'id' => 'client_123',
						'secret' => 'secret456',
					],
					'adapter' => 'Hybridauth\\Provider\\GitHub',
					'callback' => Oauth2ClientHelper::GetLandingURL(),
					'debug_mode' => Oauth2ClientLog::GetHybridauthDebugMode(),
					'scope' => 'scope789',
					'tokens' => [
						'access_token' => 'access_token1',
						'token_type' => 'token_type1',
						'refresh_token' => 'refresh_token1',
						'expires_at' => 1731454668,
					],
				],
			],
			'authorization_state' => 'HA-JYXSNR41K0D8BQHMGAOU6LI2C7TZP9FE5W3V',
		];
		$this->assertEquals($aExpected, Oauth2ClientService::GetInstance()->GetRefreshTokenConfiguration());
	}

	public function testGetRefreshTokenConfiguration_WithAdditionalCustomMappingField_MSGraph_Tenant() {
		$oObj = $this->CreateOauth2ClientWithTokens(\MicrosoftGraphOauth2Client::class, ['scope' => 'scope789', 'tenant' => 'tenant321']);
		Oauth2ClientService::GetInstance()->InitClient($oObj->Get('name'), $oObj->Get('provider'));

		$aExpected = [
			'providers' => [
				'microsoftgraph' => [
					'enabled' => true,
					'keys' => [
						'id' => 'client_123',
						'secret' => 'secret456',
					],
					'adapter' => 'Hybridauth\\Provider\\MicrosoftGraph',
					'callback' => Oauth2ClientHelper::GetLandingURL(),
					'debug_mode' => Oauth2ClientLog::GetHybridauthDebugMode(),
					'scope' => 'scope789',
					'tokens' => [
						'access_token' => 'access_token1',
						'token_type' => 'token_type1',
						'expires_at' => 1731454668,
						'id_token' => 'refresh_token1',
					],
					'tenant' => 'tenant321',
				],
			],
			'authorization_state' => 'HA-JYXSNR41K0D8BQHMGAOU6LI2C7TZP9FE5W3V',
		];
		$this->assertEquals($aExpected, Oauth2ClientService::GetInstance()->GetRefreshTokenConfiguration());
	}

	public function testGetAccessToken_NoTokenYet() {
		$oObj = $this->CreateOauth2Client(\GoogleOauth2Client::class, ['scope' => 'scope789']);
		Oauth2ClientService::GetInstance()->InitClient($oObj->Get('name'), $oObj->Get('provider'));
		$this->assertEquals(null, Oauth2ClientService::GetInstance()->GetAccessToken());
	}

	public function testGetAccessToken() {
		$oObj = $this->CreateOauth2ClientWithTokens(\GoogleOauth2Client::class, ['scope' => 'scope789']);
		Oauth2ClientService::GetInstance()->InitClient($oObj->Get('name'), $oObj->Get('provider'));
		$this->assertEquals('access_token1', Oauth2ClientService::GetInstance()->GetAccessToken());
	}

	public function testIsExpired_NoTokenYet() {
		$oObj = $this->CreateOauth2Client(\GoogleOauth2Client::class, ['scope' => 'scope789']);
		Oauth2ClientService::GetInstance()->InitClient($oObj->Get('name'), $oObj->Get('provider'));
		$this->expectException(Oauth2ClientException::class);
		$this->expectExceptionMessage('No expiration date found');
		Oauth2ClientService::GetInstance()->IsExpired();
	}

	public function testIsExpired_TokenUpToDate() {
		$sDateInTheFuture = date(\AttributeDateTime::GetSQLFormat(), strtotime('+1 HOURS'));
		$now = new \DateTime();
		$oObj = $this->CreateOauth2Client(\GoogleOauth2Client::class,
			['scope' => 'scope789', 'access_token_expiration' => $sDateInTheFuture]);
		Oauth2ClientService::GetInstance()->InitClient($oObj->Get('name'), $oObj->Get('provider'));
		$this->assertFalse(Oauth2ClientService::GetInstance()->IsExpired(),
			"expiration: $sDateInTheFuture now: ".$now->format(\AttributeDateTime::GetSQLFormat()));
	}

	public function testIsExpired_TokenExpired() {
		$sDateInTheFuture = date(\AttributeDateTime::GetSQLFormat(), strtotime('-1 HOURS'));
		$now = new \DateTime();
		$oObj = $this->CreateOauth2Client(\GoogleOauth2Client::class,
			['scope' => 'scope789', 'access_token_expiration' => $sDateInTheFuture]);
		Oauth2ClientService::GetInstance()->InitClient($oObj->Get('name'), $oObj->Get('provider'));
		$this->assertTrue(Oauth2ClientService::GetInstance()->IsExpired(),
			"expiration: $sDateInTheFuture now: ".$now->format(\AttributeDateTime::GetSQLFormat()));
	}

	public function testSaveTokens() {
		$oObj = $this->CreateOauth2Client(\GitHubOauth2Client::class, ['scope' => 'scope789']);
		Oauth2ClientService::GetInstance()->InitClient($oObj->Get('name'), $oObj->Get('provider'));

		$aTokenResponse = [
			'access_token' => 'access_token1',
			'authorization_state' => 'HA-JYXSNR41K0D8BQHMGAOU6LI2C7TZP9FE5W3V',
			'token_type' => 'bearer',
			'refresh_token' => 'refresh_token1',
			'expires_at' => '2024-11-13 00:37:48',
		];
		Oauth2ClientService::GetInstance()->SaveTokens($aTokenResponse, 'default_scope');

		$oObj->Reload();

		$this->assertEquals('scope789', $oObj->Get('scope'));
		$this->assertEquals('access_token1', $oObj->Get('access_token')->GetPassword());
		$this->assertEquals('bearer', $oObj->Get('token_type'));
		$this->assertEquals('refresh_token1', $oObj->Get('refresh_token')->GetPassword());
		$this->assertEquals('2024-11-13 00:37:48', $oObj->Get('access_token_expiration'));
		$this->assertEquals('HA-JYXSNR41K0D8BQHMGAOU6LI2C7TZP9FE5W3V', $oObj->Get('authorization_state'));
	}

	public function testSaveTokens_OverrideWithDefaultScopeWhenNotFilledIn() {
		$oObj = $this->CreateOauth2Client(\GitHubOauth2Client::class, []);
		Oauth2ClientService::GetInstance()->InitClient($oObj->Get('name'), $oObj->Get('provider'));

		$aTokenResponse = [
			'access_token' => 'access_token1',
			'authorization_state' => 'HA-JYXSNR41K0D8BQHMGAOU6LI2C7TZP9FE5W3V',
			'token_type' => 'bearer',
			'refresh_token' => 'refresh_token1',
			'expires_at' => '2024-11-13 00:37:48',
		];
		Oauth2ClientService::GetInstance()->SaveTokens($aTokenResponse, 'default_scope');

		$oObj->Reload();

		$this->assertEquals('default_scope', $oObj->Get('scope'));
		$this->assertEquals('access_token1', $oObj->Get('access_token')->GetPassword());
		$this->assertEquals('bearer', $oObj->Get('token_type'));
		$this->assertEquals('refresh_token1', $oObj->Get('refresh_token')->GetPassword());
		$this->assertEquals('2024-11-13 00:37:48', $oObj->Get('access_token_expiration'));
		$this->assertEquals('HA-JYXSNR41K0D8BQHMGAOU6LI2C7TZP9FE5W3V', $oObj->Get('authorization_state'));
	}

	public function testSaveTokens_NoRefreshParamsReturnedByIDP() {
		$oObj = $this->CreateOauth2Client(\GitHubOauth2Client::class, ['scope' => 'scope789']);
		Oauth2ClientService::GetInstance()->InitClient($oObj->Get('name'), $oObj->Get('provider'));

		$aTokenResponse = [
			'access_token' => 'access_token1',
			'authorization_state' => 'HA-JYXSNR41K0D8BQHMGAOU6LI2C7TZP9FE5W3V',
			'token_type' => 'bearer',
		];
		Oauth2ClientService::GetInstance()->SaveTokens($aTokenResponse, 'default_scope');

		$oObj->Reload();

		$this->assertEquals('scope789', $oObj->Get('scope'));
		$this->assertEquals('access_token1', $oObj->Get('access_token')->GetPassword());
		$this->assertEquals('bearer', $oObj->Get('token_type'));
		$this->assertEquals('', $oObj->Get('refresh_token')->GetPassword());
		$this->assertEquals(null, $oObj->Get('access_token_expiration'));
		$this->assertEquals('HA-JYXSNR41K0D8BQHMGAOU6LI2C7TZP9FE5W3V', $oObj->Get('authorization_state'));
	}

	public function SaveTokensWithCustomFieldsProvider() {
		return [
			'MicrosoftGraphOauth2Client' => ['MicrosoftGraphOauth2Client'],
			'GoogleOauth2Client' => ['GoogleOauth2Client'],
		];
	}

	/**
	 * @dataProvider SaveTokensWithCustomFieldsProvider
	 */
	public function testSaveTokensWithCustomFields($sProviderClass) {
		$oObj = $this->CreateOauth2Client($sProviderClass, ['scope' => 'scope789']);
		Oauth2ClientService::GetInstance()->InitClient($oObj->Get('name'), $oObj->Get('provider'));

		$aTokenResponse = [
			'access_token' => 'access_token1',
			'authorization_state' => 'HA-JYXSNR41K0D8BQHMGAOU6LI2C7TZP9FE5W3V',
			'token_type' => 'bearer',
			'id_token' => 'refresh_token1',
			'expires_at' => '2024-11-13 00:37:48',
		];
		Oauth2ClientService::GetInstance()->SaveTokens($aTokenResponse, 'default_scope');

		$oObj->Reload();

		$this->assertEquals('scope789', $oObj->Get('scope'));
		$this->assertEquals('access_token1', $oObj->Get('access_token')->GetPassword());
		$this->assertEquals('bearer', $oObj->Get('token_type'));
		$this->assertEquals('refresh_token1', $oObj->Get('refresh_token')->GetPassword());
		$this->assertEquals('2024-11-13 00:37:48', $oObj->Get('access_token_expiration'));
		$this->assertEquals('HA-JYXSNR41K0D8BQHMGAOU6LI2C7TZP9FE5W3V', $oObj->Get('authorization_state'));
	}
}
