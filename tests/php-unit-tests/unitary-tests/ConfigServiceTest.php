<?php
/**
 * @copyright   Copyright (C) 2010-2024 Combodo SARL
 * @license     http://opensource.org/licenses/AGPL-3.0
 */

namespace Combodo\iTop\Oauth2Client\Test;

use Combodo\iTop\ItopAttributeEncryptedPassword\Model\ormEncryptedPassword;
use Combodo\iTop\Oauth2Client\Controller\Oauth2ClientController;
use Combodo\iTop\Oauth2Client\Helper\Oauth2ClientHelper;
use Combodo\iTop\Oauth2Client\Helper\Oauth2ClientLog;
use Combodo\iTop\Oauth2Client\Model\ConfigService;
use Combodo\iTop\Oauth2Client\Service\HybridAuthService;
use Combodo\iTop\Test\UnitTest\ItopDataTestCase;
use GitHubOauth2Client;
use Hybridauth\Adapter\OAuth2;
use MicrosoftGraphOauth2Client;
use Hybridauth\Provider\GitHub;

class ConfigServiceTest extends ItopDataTestCase
{
	private HybridAuthService $oHybridAuthService;

	protected function setUp(): void {
		parent::setUp();

		$this->RequireOnceItopFile('env-production/combodo-oauth2-client/vendor/autoload.php');

		$this->oHybridAuthService = $this->createMock(HybridAuthService::class);
		HybridAuthService::SetInstance($this->oHybridAuthService);
	}

	protected function tearDown(): void {
		parent::tearDown();

		HybridAuthService::SetInstance(null);
	}

	public function GetClassNameProvider()
	{
		return [
			[ 'Github', 'Github' ],
			[ 'Hybridauth\\\\Provider\\\\Github', 'Github' ],
			[ 'Hybridauth\Provider\Github', 'Github' ],
		];
	}

	/**
	 * @dataProvider GetClassNameProvider
	 */
	public function testGetClassName($sProvider, $sExpectedRes){
		$sProviderName = $this->InvokeNonPublicMethod(ConfigService::class, 'GetClassName', ConfigService::GetInstance(), [$sProvider]);
		$this->assertEquals($sExpectedRes, $sProviderName, $sProvider);
	}

	public function testResetTokens() {
		$sClientId = 'client_123';
		$sClientSecret = 'secret456';
		$sName = 'webhook';
		$aFields = [
			'name' => $sName,
			'client_id' => $sClientId,
			'client_secret' => $sClientSecret,
			'scope' => 'toto',
			'access_token' => 'access_token1',
			'token_type' => 'token_type1',
			'refresh_token' => 'refresh_token1',
			'access_token_expiration' => '2024-11-13 00:37:48',
		];

		/** @var \Oauth2Client $oOauth2Client */
		$oOauth2Client = $this->createObject(GitHubOauth2Client::class,
			$aFields
		);

		foreach ($aFields as $sId => $sExpectedVal){
			$sVal = $oOauth2Client->Get($sId);
			if ($sVal instanceof ormEncryptedPassword) {
				$this->assertEquals($sExpectedVal, $sVal->GetPassword());
			} else {
				$this->assertEquals($sExpectedVal, $sVal);
			}
		}

		$aFields = [
			'name' => $sName,
			'client_id' => $sClientId,
			'client_secret' => $sClientSecret,
			'scope' => 'toto',
			'access_token' => '',
			'token_type' => '',
			'refresh_token' => '',
			'access_token_expiration' => '',
		];

		ConfigService::GetInstance()->ResetTokens($oOauth2Client);
		foreach ($aFields as $sId => $sExpectedVal){
			$sVal = $oOauth2Client->Get($sId);
			if ($sVal instanceof ormEncryptedPassword) {
				$this->assertEquals($sExpectedVal, $sVal->GetPassword());
			} else {
				$this->assertEquals($sExpectedVal, $sVal);
			}
		}
	}

	public function testGetOauth2Client_Github_NoTokenYet() {
		$sClientId = 'client_123';
		$sClientSecret = 'secret456';

		$sName = 'webhook';
		$this->createObject(GitHubOauth2Client::class,
			['name' => $sName, 'client_id' => $sClientId, 'client_secret' => $sClientSecret]
		);

		$aExpected = [
			'providers' => [
				'github' => [
					'enabled' => true,
					'keys' => [
						'id' => $sClientId,
						'secret' => $sClientSecret,
					],
					'callback' => ConfigService::GetInstance()->GetLandingURL(),
					'debug_mode' => Oauth2ClientLog::GetHybridauthDebugMode(),
				],
			],
		];

		$oOauth2 = $this->createMock(OAuth2::class);
		$this->oHybridAuthService->expects($this->once())
			->method('GetOauth2')
			->with($aExpected, 'github')
			->willReturn($oOauth2);

		$oOauth2Client = ConfigService::GetInstance()->GetOauth2Client($sName, 'Hybridauth\Provider\Github');

		$this->assertEquals($oOauth2, $oOauth2Client->GetOauth2());
	}

	public function testGetOauth2Client_Github_WithAccessAndRefreshTokensToken() {
		$sClientId = 'client_123';
		$sClientSecret = 'secret456';

		$sName = 'webhook';
		$this->createObject(GitHubOauth2Client::class,
			[
				'name' => $sName,
				'client_id' => $sClientId,
				'client_secret' => $sClientSecret,
				'access_token' => 'access_token7',
				'access_token_expiration' => '2024-11-13 00:37:48',
				'refresh_token' => 'refresh_token8',
				'refresh_token_expiration' => '2025-11-13 00:37:48',
				'token_type' => 'bearer',
				'scope' => 'any scope',
			]
		);

		$aExpected = [
			'providers' => [
				'github' => [
					'enabled' => true,
					'keys' => [
						'id' => $sClientId,
						'secret' => $sClientSecret,
					],
					'callback' => ConfigService::GetInstance()->GetLandingURL(),
					'debug_mode' => Oauth2ClientLog::GetHybridauthDebugMode(),
					'scope' => 'any scope',
					'tokens' => [
						'access_token' => 'access_token7',
		                'token_type' => 'bearer',
		                'refresh_token' => 'refresh_token8',
		                'expires_at' => 1731454668,
					],
				],
			],
		];

		$oOauth2 = $this->createMock(Oauth2::class);
		$this->oHybridAuthService->expects($this->once())
			->method('GetOauth2')
			->with($aExpected, 'github')
			->willReturn($oOauth2);

		$oOauth2Client = ConfigService::GetInstance()->GetOauth2Client($sName, 'Hybridauth\Provider\Github');

		$this->assertEquals($oOauth2, $oOauth2Client->GetOauth2());
	}

	public function testGetOauth2Client_Github_WithAccessAndRefreshTokensToken_RefreshRequired() {
		$sClientId = 'client_123';
		$sClientSecret = 'secret456';

		$sName = 'webhook';
		$this->createObject(GitHubOauth2Client::class,
			[
				'name' => $sName,
				'client_id' => $sClientId,
				'client_secret' => $sClientSecret,
				'access_token' => 'access_token7',
				'access_token_expiration' => '2024-11-13 00:37:48',
				'refresh_token' => 'refresh_token8',
				'refresh_token_expiration' => '2025-11-13 00:37:48',
				'token_type' => 'bearer',
				'scope' => 'any scope',
			]
		);

		$aExpected = [
			'providers' => [
				'github' => [
					'enabled' => true,
					'keys' => [
						'id' => $sClientId,
						'secret' => $sClientSecret,
					],
					'callback' => ConfigService::GetInstance()->GetLandingURL(),
					'debug_mode' => Oauth2ClientLog::GetHybridauthDebugMode(),
					'scope' => 'any scope',
				],
			],
		];

		$oOauth2 = $this->createMock(Oauth2::class);
		$this->oHybridAuthService->expects($this->once())
			->method('GetOauth2')
			->with($aExpected, 'github')
			->willReturn($oOauth2);

		$oOauth2Client = ConfigService::GetInstance()->GetOauth2Client($sName, 'Hybridauth\Provider\Github', true);

		$this->assertEquals($oOauth2, $oOauth2Client->GetOauth2());
	}

	public function testSetTokens_Github() {
		$sClientId = 'client_123';
		$sClientSecret = 'secret456';

		$sName = 'webhook';
		/** @var \Oauth2Client $oOauth2Client */
		$oOauth2Client = $this->createObject(GitHubOauth2Client::class,
			['name' => $sName, 'client_id' => $sClientId, 'client_secret' => $sClientSecret, 'scope' => 'toto']
		);

		$oGithubAdapter = $this->createMock(GitHub::class);
		$oGithubAdapter->expects($this->once())
			->method('getAccessToken')
			->willReturn(
				[
					'access_token' => 'ghu_xxx',
					'token_type' => 'bearer',
					'refresh_token' => 'ghr_yyy',
					'expires_at' => 1731454668,
				]
			);
		$oOauth2Client->SetOauth2($oGithubAdapter);

		ConfigService::GetInstance()->SetTokens($oOauth2Client);
		$oOauth2Client->Reload();

		$this->assertEquals('toto', $oOauth2Client->Get('scope'));
		$this->assertEquals('ghu_xxx', $oOauth2Client->Get('access_token')->GetPassword());
		$this->assertEquals('bearer', $oOauth2Client->Get('token_type'));
		$this->assertEquals('ghr_yyy', $oOauth2Client->Get('refresh_token')->GetPassword());
		$this->assertEquals('2024-11-13 00:37:48', $oOauth2Client->Get('access_token_expiration'));
	}

	public function testSetTokens_Github_ScopeNotSet_UseProviderScope() {
		$sClientId = 'client_123';
		$sClientSecret = 'secret456';

		$sName = 'webhook';
		/** @var \Oauth2Client $oOauth2Client */
		$oOauth2Client = $this->createObject(GitHubOauth2Client::class,
			['name' => $sName, 'client_id' => $sClientId, 'client_secret' => $sClientSecret]
		);

		$oGithubAdapter = $this->createMock(GitHub::class);
		$oGithubAdapter->expects($this->once())
			->method('getAccessToken')
			->willReturn(
				[
					'access_token' => 'ghu_xxx',
					'token_type' => 'bearer',
					'refresh_token' => 'ghr_yyy',
					'expires_at' => 1731454668,
				]
			);
		$oOauth2Client->SetOauth2($oGithubAdapter);
		ConfigService::GetInstance()->SetTokens($oOauth2Client);
		$oOauth2Client->Reload();

		$this->assertEquals('user:email', $oOauth2Client->Get('scope'));
		$this->assertEquals('ghu_xxx', $oOauth2Client->Get('access_token')->GetPassword());
		$this->assertEquals('bearer', $oOauth2Client->Get('token_type'));
		$this->assertEquals('ghr_yyy', $oOauth2Client->Get('refresh_token')->GetPassword());
		$this->assertEquals('2024-11-13 00:37:48', $oOauth2Client->Get('access_token_expiration'));
	}

	public function GetConnectUrlProvider() {
		return [
			'reset with GitHub' => [ 'class' => GitHubOauth2Client::class, 'action' => 'reset' ],
			'NO reset with MS' => [ 'class' => MicrosoftGraphOauth2Client::class, 'action' => 'resfresh_token' ],
		];
	}

	/**
	 * @dataProvider GetConnectUrlProvider
	 */
	public function testGetConnectUrl(string $sClass, string $sAction) {
		$oOauth2Client = $this->createObject($sClass,
			['name' => 'testname', 'client_id' => 'sClientId', 'client_secret' => 'sClientSecret']
		);

		$sProvider = urlencode(base64_encode($oOauth2Client->Get('provider')));
		$sUrl = ConfigService::GetInstance()->GetConnectUrl($oOauth2Client, $sAction);
		$sExpectedUrl = \utils::GetAbsoluteUrlModulesRoot().Oauth2ClientHelper::MODULE_NAME."/connect.php?name=testname&provider=$sProvider&action=$sAction";

		$this->assertEquals($sExpectedUrl, $sUrl);
	}

}
