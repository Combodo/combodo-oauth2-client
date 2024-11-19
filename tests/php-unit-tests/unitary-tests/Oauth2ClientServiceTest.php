<?php

namespace Combodo\iTop\Oauth2Client\Test;

use Combodo\iTop\Application\Helper\Session;
use Combodo\iTop\Oauth2Client\Model\ConfigService;
use Combodo\iTop\Oauth2Client\Service\HybridAuthService;
use Combodo\iTop\Oauth2Client\Service\Oauth2ClientService;
use Combodo\iTop\Test\UnitTest\ItopDataTestCase;
use GitHubOauth2Client;
use Hybridauth\Adapter\OAuth2;
use Hybridauth\Provider\GitHub;
use MetaModel;
use Oauth2Client;

/**
 * @runClassInSeparateProcess Required because PHPUnit outputs something earlier, thus causing the headers to be sent
 */
class Oauth2ClientServiceTest extends ItopDataTestCase
{
	const USE_TRANSACTION = false;
	private ConfigService $oConfigService;
	private HybridAuthService $oHybridAuthService;

	protected function setUp(): void {
		parent::setUp();
		//Session::$bAllowCLI = true;

		$this->RequireOnceItopFile('env-production/combodo-oauth2-client/vendor/autoload.php');

		$this->oConfigService = $this->createMock(ConfigService::class);
		ConfigService::SetInstance($this->oConfigService);

		$this->oHybridAuthService = $this->createMock(HybridAuthService::class);
		HybridAuthService::SetInstance($this->oHybridAuthService);
	}

	protected function tearDown(): void
	{
		parent::tearDown();
		ConfigService::SetInstance(null);
		HybridAuthService::SetInstance(null);

		//Session::$bAllowCLI = false;
	}

	public function ConnectProvider()
	{
		return [
			'no reset' => [ true ],
			'reset required' => [ false ],
		];
	}

	/**
	 * @dataProvider ConnectProvider
	 */
	public function testConnect_NoDisconnectionFirst(bool $bResetToken)
	{
		$oOauth2Client = $this->createMock(Oauth2Client::class);
		$this->oConfigService->expects($this->once())
			->method('GetOauth2Client')
			->with('webhook', 'Hybridauth\Provider\Github', $bResetToken)
			->willReturn($oOauth2Client);

		$oOauth2 = $this->createMock(OAuth2::class);
		$oOauth2Client->expects($this->once())
			->method('GetOauth2')
			->willReturn($oOauth2);

		$oOauth2->expects($this->once())
			->method('isConnected')
			->willReturn(false);

		$oOauth2->expects($this->never())
			->method('disconnect');

		$oOauth2->expects($this->once())
			->method('authenticate');

		$res = Oauth2ClientService::GetInstance()->Connect('webhook', 'Hybridauth\Provider\Github', $bResetToken);
		$this->assertEquals($oOauth2, $res);
	}
	
	public function testStoreTokens()
	{
		$oOauth2Client = $this->createMock(Oauth2Client::class);

		$this->oConfigService->expects($this->once())
			->method('GetOauth2Client')
			->with('webhook', 'Hybridauth\Provider\Github')
			->willReturn($oOauth2Client);

		$oOauth2 = $this->createMock(OAuth2::class);
		$oOauth2Client->expects($this->once())
			->method('GetOauth2')
			->willReturn($oOauth2);


		$oOauth2->expects($this->once())
			->method('authenticate');

		$this->oConfigService->expects($this->once())
			->method('SetTokens')
			->with($oOauth2Client);

		$res = Oauth2ClientService::GetInstance()->StoreTokens('webhook', 'Hybridauth\Provider\Github');
		$this->assertEquals($oOauth2, $res);
	}

	private function GetOauth2client() : Oauth2Client
	{
		$aFields = [
			'name' => 'webhook',
			'client_id' => 'client_123',
			'client_secret' => 'secret456',
			'scope' => 'toto',
			'access_token' => 'access_token1',
			'token_type' => 'token_type1',
			'refresh_token' => 'refresh_token1',
			'access_token_expiration' => '2024-11-12 00:37:48',
		];

		/** @var \Oauth2Client $oOauth2Client */
		$oOauth2Client = $this->createObject(GitHubOauth2Client::class,
			$aFields
		);
		return $oOauth2Client;
	}

	public function testGetToken_NoRefreshTokenSupported()
	{
		//dont mock ConnfigService here
		ConfigService::SetInstance(null);

		$oOauth2 = $this->createMock(GitHub::class);
		$this->oHybridAuthService->expects($this->once())
			->method('GetOauth2')
			->willReturn($oOauth2);

		$oOauth2Client = $this->GetOauth2client();

		$oOauth2->expects($this->once())
			->method('isConnected')
			->willReturn(true);

		$oOauth2->expects($this->once())
			->method('maintainToken');

		$oOauth2->expects($this->once())
			->method('hasAccessTokenExpired')
			->willReturn(false);

		$oOauth2->expects($this->never())
			->method('refreshAccessToken');

		$oOauth2->expects($this->never())
			->method('getAccessToken');

		$res = Oauth2ClientService::GetInstance()->GetToken($oOauth2Client);
		$this->assertEquals('access_token1', $res);
		$this->assertEquals('access_token1', $oOauth2Client->Get('access_token')->GetPassword());
	}

	public function testGetToken_RefreshTokenTrigger()
	{
		//dont mock ConnfigService here
		ConfigService::SetInstance(null);

		$oOauth2Client = $this->GetOauth2client();

		$oOauth2 = $this->createMock(GitHub::class);
		$this->oHybridAuthService->expects($this->once())
			->method('GetOauth2')
			->willReturn($oOauth2);

		$oOauth2->expects($this->once())
			->method('isConnected')
			->willReturn(true);

		$oOauth2->expects($this->once())
			->method('maintainToken');

		$oOauth2->expects($this->once())
			->method('hasAccessTokenExpired')
			->willReturn(true);

		$oOauth2->expects($this->once())
			->method('refreshAccessToken');

		$oOauth2->expects($this->once())
			->method('getAccessToken')
			->willReturn(
				[
					'access_token' => 'ghu_xxx',
					'token_type' => 'bearer',
					'refresh_token' => 'ghr_yyy',
					'expires_at' => 1731454668,
				]
			);

		$this->assertEquals('access_token1', $oOauth2Client->Get('access_token')->GetPassword());

		$res = Oauth2ClientService::GetInstance()->GetToken($oOauth2Client);

		$this->assertEquals('ghu_xxx', $res);
		$this->assertEquals('ghu_xxx', $oOauth2Client->Get('access_token')->GetPassword());
		$this->assertEquals('ghr_yyy', $oOauth2Client->Get('refresh_token')->GetPassword());
		$this->assertEquals('bearer', $oOauth2Client->Get('token_type'));
		$this->assertEquals('2024-11-13 00:37:48', $oOauth2Client->Get('access_token_expiration'));
	}

	/*public function testGetToken() {
		//session_start();
		//Session::$bAllowCLI = false;
		$this->assertNull(Session::$iSessionId);
		Session::Start();
		$this->assertNotNull(Session::$iSessionId);
		$_SERVER['REMOTE_ADDR'] = '1.2.3.4';

		$oGitHubOauth2Client = MetaModel::GetObject(GitHubOauth2Client::class, 4);
		$sToken = $oGitHubOauth2Client->Get('access_token')->GetPassword();
		$this->assertEquals($sToken, Oauth2ClientService::GetInstance()->GetToken($oGitHubOauth2Client));
	}*/
}
