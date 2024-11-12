<?php
/**
 * @copyright   Copyright (C) 2010-2024 Combodo SARL
 * @license     http://opensource.org/licenses/AGPL-3.0
 */

namespace Combodo\iTop\MFATotp\Test;

use Combodo\iTop\Oauth2Client\Helper\Oauth2ClientLog;
use Combodo\iTop\Oauth2Client\Model\ConfigService;
use Combodo\iTop\Test\UnitTest\ItopDataTestCase;
use GithubOauth2Client;
use Hybridauth\Provider\GitHub;

class ConfigServiceTest extends ItopDataTestCase
{
	protected function setUp(): void {
		parent::setUp();

		$this->RequireOnceItopFile('env-production/combodo-oauth2-client/vendor/autoload.php');
	}

	public function GetHybridauthProviderNameProvider()
	{
		return [
			[ 'Github', 'Github' ],
			[ 'Hybridauth\\\\Provider\\\\Github', 'Github' ],
			[ 'Hybridauth\Provider\Github', 'Github' ],
		];
	}

	/**
	 * @dataProvider GetHybridauthProviderNameProvider
	 */
	public function testGetHybridauthProviderName($sProvider, $sExpectedRes){
		$this->assertEquals($sExpectedRes, ConfigService::GetInstance()->GetHybridauthProviderName($sProvider), $sProvider);
	}

	public function testGetConfig_Github_NoTokenYet() {
		$sClientId = 'client_123';
		$sClientSecret = 'secret456';

		$sName = 'webhook';
		$oOauth2Client = $this->createObject(GithubOauth2Client::class,
			['name' => $sName, 'client_id' => $sClientId, 'client_secret' => $sClientSecret]
		);

		list($sProviderName, $aConfig) = ConfigService::GetInstance()->GetConfig($sName, 'Hybridauth\Provider\Github');
		$this->assertEquals('github', $sProviderName);
		$aExpected = [
			'providers' => [
				'github' => [
					'enabled' => true,
					'keys' => [
						'id' => $sClientId,
						'secret' => $sClientSecret,
					],
					'callback' => ConfigService::GetInstance()->GetLandingURL($oOauth2Client),
					'debug_mode' => Oauth2ClientLog::GetHybridauthDebugMode(),
				]
			]
		];
		$this->assertEquals($aExpected, $aConfig);
	}

	public function testGetConfig_Github_WithAccessAndRefreshTokensToken() {
		$sClientId = 'client_123';
		$sClientSecret = 'secret456';

		$sName = 'webhook';
		$oOauth2Client = $this->createObject(GithubOauth2Client::class,
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

		list($sProviderName, $aConfig) = ConfigService::GetInstance()->GetConfig($sName, 'Hybridauth\Provider\Github');
		$this->assertEquals('github', $sProviderName);
		$aExpected = [
			'providers' => [
				'github' => [
					'enabled' => true,
					'keys' => [
						'id' => $sClientId,
						'secret' => $sClientSecret,
					],
					'callback' => ConfigService::GetInstance()->GetLandingURL($oOauth2Client),
					'debug_mode' => Oauth2ClientLog::GetHybridauthDebugMode(),
					'scope' => 'any scope',
					'tokens' => [
						'access_token' => 'access_token7',
		                'token_type' => 'bearer',
		                'refresh_token' => 'refresh_token8',
		                'expires_at' => '2024-11-13 00:37:48',
					],
				]
			]
		];
		$this->assertEquals($aExpected, $aConfig);
	}

	public function testSetTokens_Github() {
		$sClientId = 'client_123';
		$sClientSecret = 'secret456';

		$sName = 'webhook';
		$oOauth2Client = $this->createObject(GithubOauth2Client::class,
			['name' => $sName, 'client_id' => $sClientId, 'client_secret' => $sClientSecret, 'scope' => 'toto']
		);

		$aConfig = ['scope' => 'toto'];
		$oGithubAdapter = $this->createMock(GitHub::class);
		$oGithubAdapter->expects($this->once())
			->method('getAccessToken')
			->willReturn(
				[
					'access_token' => 'ghu_xxx',
					//'access_token_secret' => '',
					'token_type' => 'bearer',
					'refresh_token' => 'ghr_yyy',
					'expires_at' => '2024-11-12 00:37:48',
				]
			);
		ConfigService::GetInstance()->SetTokens($sName, 'Hybridauth\Provider\Github', $oGithubAdapter, $aConfig);
		$oOauth2Client->Reload();

		$this->assertEquals('toto', $oOauth2Client->Get('scope'));
		$this->assertEquals('ghu_xxx', $oOauth2Client->Get('access_token'));
		$this->assertEquals('bearer', $oOauth2Client->Get('token_type'));
		$this->assertEquals('ghr_yyy', $oOauth2Client->Get('refresh_token'));
		$this->assertEquals('2024-11-12 00:37:48', $oOauth2Client->Get('access_token_expiration'));
	}

	public function testSetTokens_Github_ScopeNotSet_UseProviderScope() {
		$sClientId = 'client_123';
		$sClientSecret = 'secret456';

		$sName = 'webhook';
		$oOauth2Client = $this->createObject(GithubOauth2Client::class,
			['name' => $sName, 'client_id' => $sClientId, 'client_secret' => $sClientSecret]
		);

		$aConfig = [];
		$oGithubAdapter = $this->createMock(GitHub::class);
		$oGithubAdapter->expects($this->once())
			->method('getAccessToken')
			->willReturn(
				[
					'access_token' => 'ghu_xxx',
					//'access_token_secret' => '',
					'token_type' => 'bearer',
					'refresh_token' => 'ghr_yyy',
					'expires_at' => '2024-11-12 00:37:48',
				]
			);
		ConfigService::GetInstance()->SetTokens($sName, 'Hybridauth\Provider\Github', $oGithubAdapter, $aConfig);
		$oOauth2Client->Reload();

		$this->assertEquals('user:email', $oOauth2Client->Get('scope'));
		$this->assertEquals('ghu_xxx', $oOauth2Client->Get('access_token'));
		$this->assertEquals('bearer', $oOauth2Client->Get('token_type'));
		$this->assertEquals('ghr_yyy', $oOauth2Client->Get('refresh_token'));
		$this->assertEquals('2024-11-12 00:37:48', $oOauth2Client->Get('access_token_expiration'));
	}

}
