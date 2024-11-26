<?php

namespace Combodo\iTop\Oauth2Client\Test\HybridAuth;

use Combodo\iTop\Oauth2Client\Helper\Oauth2ClientHelper;
use Combodo\iTop\Oauth2Client\Helper\Oauth2ClientLog;
use Combodo\iTop\Oauth2Client\HybridAuth\AdapterInterfaceFactoryService;
use Combodo\iTop\Oauth2Client\HybridAuth\AdapterService;
use Combodo\iTop\Test\UnitTest\ItopDataTestCase;
use Hybridauth\Adapter\AdapterInterface;
use Hybridauth\Logger\Logger;
use Hybridauth\Provider\GitHub;
use Hybridauth\Provider\Google;
use Hybridauth\Provider\MicrosoftGraph;
use Hybridauth\Storage\StorageInterface;

class AdapterServiceTest extends ItopDataTestCase {
	private AdapterInterfaceFactoryService $oAdapterFabrikService;
	private StorageInterface $oStorageInterface;

	protected function setUp(): void {
		parent::setUp();
		$this->RequireOnceItopFile('env-production/combodo-oauth2-client/vendor/autoload.php');
	}

	protected function tearDown(): void {
		parent::tearDown();
	}

	private function MockAdapterFabrikService($sProviderName, array $aConfig, AdapterInterface $oAuth2, ?string $sExpectedAuthorizationState=null) {
		$this->oAdapterFabrikService = $this->createMock(AdapterInterfaceFactoryService::class);
		AdapterInterfaceFactoryService::SetInstance($this->oAdapterFabrikService);
		$this->oAdapterFabrikService->expects($this->once())
			->method('GetAdapterInterface')
			->with($sProviderName, $aConfig)
			->willReturn($oAuth2);

		if (is_null($sExpectedAuthorizationState)){
			$oAuth2->expects($this->never())->method('getStorage');
		} else {
			$oAuth2->expects($this->once())
				->method('getStorage')
				->willReturn($this->oStorageInterface);

			$this->oStorageInterface->expects($this->once())
				->method('set')
				->with("$sProviderName.authorization_state", $sExpectedAuthorizationState);
		}
	}

	public function testAuthenticate_NoAuthorizationStateYet() {
		$oAuth2 = $this->createMock(Google::class);
		$sProvider = 'Hybridauth\\Provider\\Google';
		$aConfig = [
			'providers' => [
				'google' => [
					'enabled' => true,
					'keys' => [
						'id' => 'client_123',
						'secret' => 'secret456',
					],
					'adapter' => $sProvider,
					'callback' => Oauth2ClientHelper::GetLandingURL(),
					'debug_mode' => Oauth2ClientLog::GetHybridauthDebugMode(),
					'scope' => 'scope789',
				],
			],
		];

		$this->oStorageInterface = $this->createMock(StorageInterface::class);
		$this->MockAdapterFabrikService('google', $aConfig, $oAuth2);

		$oAuth2->expects($this->once())
			->method('disconnect');

		$oAuth2->expects($this->once())
			->method('authenticate');

		AdapterService::GetInstance()->Init('webhook', $sProvider);
		AdapterService::GetInstance()->Authenticate($aConfig);
	}

	private function GetTokenResponseExample() : array
	{
		return [
			'access_token' => 'access_token1',
			'authorization_state' => 'HA-JYXSNR41K0D8BQHMGAOU6LI2C7TZP9FE5W3V',
			'token_type' => 'bearer',
			'refresh_token' => 'refresh_token1',
			'expires_at' => '2024-11-13 00:37:48',
		];
	}

	public function testAuthenticateFinish_IdpAnswerByHttpPost() {
		$_SERVER = ['REQUEST_METHOD' => 'POST' ];
		$_POST = ['state' => 'auth_state123' ];

		$oAuth2 = $this->createMock(Google::class);
		$sProvider = 'Hybridauth\\Provider\\Google';
		$aConfig = [
			'providers' => [
				'google' => [
					'enabled' => true,
					'keys' => [
						'id' => 'client_123',
						'secret' => 'secret456',
					],
					'adapter' => $sProvider,
					'callback' => Oauth2ClientHelper::GetLandingURL(),
					'debug_mode' => Oauth2ClientLog::GetHybridauthDebugMode(),
					'scope' => 'scope789',
				],
			],
		];

		$this->oStorageInterface = $this->createMock(StorageInterface::class);
		$this->MockAdapterFabrikService('google', $aConfig, $oAuth2);

		$oAuth2->expects($this->never())
			->method('disconnect');

		$oAuth2->expects($this->once())
			->method('authenticate');

		$aTokenExample = $this->GetTokenResponseExample();
		$oAuth2->expects($this->once())
			->method('getAccessToken')
			->willReturn($aTokenExample);

		$aExpectedRes = array_merge($aTokenExample, ['authorization_state' => 'auth_state123']);
		AdapterService::GetInstance()->Init('webhook', $sProvider);
		$this->assertEquals($aExpectedRes, AdapterService::GetInstance()->AuthenticateFinish($aConfig));
	}

	public function testAuthenticateFinish_IdpAnswerByHttpGet() {
		$_SERVER = ['REQUEST_METHOD' => 'GET' ];
		$_REQUEST = ['state' => 'auth_state123' ];

		$oAuth2 = $this->createMock(Google::class);
		$sProvider = 'Hybridauth\\Provider\\Google';
		$aConfig = [
			'providers' => [
				'google' => [
					'enabled' => true,
					'keys' => [
						'id' => 'client_123',
						'secret' => 'secret456',
					],
					'adapter' => $sProvider,
					'callback' => Oauth2ClientHelper::GetLandingURL(),
					'debug_mode' => Oauth2ClientLog::GetHybridauthDebugMode(),
					'scope' => 'scope789',
				],
			],
		];

		$this->oStorageInterface = $this->createMock(StorageInterface::class);
		$this->MockAdapterFabrikService('google', $aConfig, $oAuth2);

		$oAuth2->expects($this->never())
			->method('disconnect');

		$oAuth2->expects($this->once())
			->method('authenticate');

		$aTokenExample = $this->GetTokenResponseExample();
		$oAuth2->expects($this->once())
			->method('getAccessToken')
			->willReturn($aTokenExample);

		$aExpectedRes = array_merge($aTokenExample, ['authorization_state' => 'auth_state123']);
		AdapterService::GetInstance()->Init('webhook', $sProvider);
		$this->assertEquals($aExpectedRes, AdapterService::GetInstance()->AuthenticateFinish($aConfig));
	}

	public function testRefreshToken_ByGet() {
		$_SERVER = ['REQUEST_METHOD' => 'GET' ];
		$sAuthorizationState = 'auth_state123';
		$_REQUEST = ['state' => $sAuthorizationState];

		$sProvider = 'Hybridauth\Provider\GitHub';
		$oAuth2 = $this->createMock($sProvider);
		$sProviderName = 'github';
		$aConfig = [
			'providers' => [
				$sProviderName => [
					'enabled' => true,
					'keys' => [
						'id' => 'client_123',
						'secret' => 'secret456',
					],
					'adapter' => $sProvider,
					'callback' => Oauth2ClientHelper::GetLandingURL(),
					'debug_mode' => Oauth2ClientLog::GetHybridauthDebugMode(),
					'scope' => 'scope789',
					'tokens' => [
						'access_token' => 'access_token1',
						'authorization_state' => 'HA-JYXSNR41K0D8BQHMGAOU6LI2C7TZP9FE5W3V',
						'token_type' => 'bearer',
						'refresh_token' => 'refresh_token1',
						'expires_at' => 1731454668,
					],
				],
			],
			'authorization_state' => $sAuthorizationState
		];

		$this->oStorageInterface = $this->createMock(StorageInterface::class);
		$this->MockAdapterFabrikService($sProviderName, $aConfig, $oAuth2, $sAuthorizationState);

		$oAuth2->expects($this->never())
			->method('disconnect');

		$oAuth2->expects($this->once())
			->method('maintainToken');

		$oAuth2->expects($this->once())
			->method('hasAccessTokenExpired')
			->willReturn(true);

		$oAuth2->expects($this->once())
			->method('refreshAccessToken')
			->willReturn("OK");

		$aTokenExample = $this->GetTokenResponseExample();
		$oAuth2->expects($this->once())
			->method('getAccessToken')
			->willReturn($aTokenExample);

		$aExpectedRes = array_merge($aTokenExample, ['authorization_state' => $sAuthorizationState]);
		AdapterService::GetInstance()->Init('webhook', $sProvider);
		$this->assertEquals($aExpectedRes, AdapterService::GetInstance()->RefreshToken($aConfig));
	}

	public function testGetDefaultScope() {
		$oAuth2 = $this->createMock(MicrosoftGraph::class);
		$sProvider = 'Hybridauth\\Provider\\MicrosoftGraph';
		$aConfig = [
			'providers' => [
				'microsoftgraph' => [
					'enabled' => true,
					'keys' => [
						'id' => 'client_123',
						'secret' => 'secret456',
					],
					'adapter' => $sProvider,
					'callback' => Oauth2ClientHelper::GetLandingURL(),
					'debug_mode' => Oauth2ClientLog::GetHybridauthDebugMode(),
					'scope' => 'scope789',
				],
			],
		];

		$this->oStorageInterface = $this->createMock(StorageInterface::class);
		$this->MockAdapterFabrikService('microsoftgraph', $aConfig, $oAuth2);

		AdapterService::GetInstance()->Init('webhook', $sProvider);
		AdapterService::GetInstance()->InitOauth2($aConfig);
		$this->assertEquals("openid user.read contacts.read offline_access", AdapterService::GetInstance()->GetDefaultScope());
	}

	public function testListProviders() {
		$aRes = AdapterService::GetInstance()->ListProviders();
		$this->assertContains("Google", $aRes, var_export($aRes, true));
		$this->assertContains("MicrosoftGraph", $aRes, var_export($aRes, true));
		//$this->assertContains("HeadlessItop", $aRes, var_export($aRes, true));
	}
}
