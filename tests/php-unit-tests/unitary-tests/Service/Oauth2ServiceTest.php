<?php

namespace Combodo\iTop\Oauth2Client\Test\Service;

use Combodo\iTop\Oauth2Client\Helper\Oauth2ClientException;
use Combodo\iTop\Oauth2Client\HybridAuth\AdapterService;
use Combodo\iTop\Oauth2Client\Model\Oauth2ClientService;
use Combodo\iTop\Oauth2Client\Service\Oauth2Service;
use Combodo\iTop\Test\UnitTest\ItopDataTestCase;
use Oauth2Client;

class Oauth2ServiceTest extends ItopDataTestCase {
	private Oauth2ClientService $oOauth2ClientService;
	private AdapterService $oAdapterService;

	protected function setUp(): void {
		parent::setUp();
		$this->RequireOnceItopFile('env-production/combodo-oauth2-client/vendor/autoload.php');

		$this->oAdapterService = $this->createMock(AdapterService::class);
		AdapterService::SetInstance($this->oAdapterService);
		$this->oOauth2ClientService = $this->createMock(Oauth2ClientService::class);
		Oauth2ClientService::SetInstance($this->oOauth2ClientService);
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


	public function testAuthenticate_SimulateIDPRedirectionViaAnException() {
		$obj = $this->CreateOauth2Client();
		$sName = $obj->Get('name');
		$sProvider = $obj->Get('provider');

		$this->oOauth2ClientService->expects($this->once())
			->method('InitClient')
			->with($sName, $sProvider);

		$this->oAdapterService->expects($this->once())
			->method('Init')
			->with($sName, $sProvider);
		Oauth2Service::GetInstance()->Init($sName, $sProvider);

		$aConfig = ["shadok => 'gabuzomeu"];
		$this->oOauth2ClientService->expects($this->once())
			->method('GetAuthenticateConfiguration')
			->willReturn($aConfig);

		$this->oAdapterService->expects($this->once())
			->method('Authenticate')
			->with($aConfig)
			->willThrowException(new Oauth2ClientException("redirection simulated here"));

		$this->expectException(\Exception::class);
		Oauth2Service::GetInstance()->Authenticate();
	}

	public function testAuthenticate_HeadlessIDP() {
		$obj = $this->CreateOauth2Client();
		$sName = $obj->Get('name');
		$sProvider = $obj->Get('provider');

		$this->oOauth2ClientService->expects($this->once())
			->method('InitClient')
			->with($sName, $sProvider);

		$this->oAdapterService->expects($this->once())
			->method('Init')
			->with($sName, $sProvider);
		Oauth2Service::GetInstance()->Init($sName, $sProvider);

		$aConfig = ["shadok => 'gabuzomeu"];
		$this->oOauth2ClientService->expects($this->exactly(2))
			->method('GetAuthenticateConfiguration')
			->willReturn($aConfig);

		$this->oAdapterService->expects($this->once())
			->method('Authenticate')
			->with($aConfig);

		$aTokenResponse = ["a"=> "b"];
		$this->oAdapterService->expects($this->once())
			->method('AuthenticateFinish')
			->willReturn($aTokenResponse);

		$sDefaultScope="defaultScope";
		$this->oAdapterService->expects($this->once())
			->method('GetDefaultScope')
			->willReturn($sDefaultScope);

		$this->oOauth2ClientService->expects($this->once())
			->method('SaveTokens')
			->with($aTokenResponse, $sDefaultScope);

		$sAccessToken = 'token123';
		$this->oOauth2ClientService->expects($this->once())
			->method('GetAccessToken')
			->willReturn($sAccessToken);

		$this->assertEquals($sAccessToken, Oauth2Service::GetInstance()->Authenticate());
	}

	public function testAuthenticateFinish() {
		$obj = $this->CreateOauth2Client();
		$sName = $obj->Get('name');
		$sProvider = $obj->Get('provider');

		$this->oOauth2ClientService->expects($this->once())
			->method('InitClient')
			->with($sName, $sProvider);

		$this->oAdapterService->expects($this->once())
			->method('Init')
			->with($sName, $sProvider);
		Oauth2Service::GetInstance()->Init($sName, $sProvider);

		$aConfig = ["shadok => 'gabuzomeu"];
		$this->oOauth2ClientService->expects($this->exactly(1))
			->method('GetAuthenticateConfiguration')
			->willReturn($aConfig);

		$aTokenResponse = ["a"=> "b"];
		$this->oAdapterService->expects($this->once())
			->method('AuthenticateFinish')
			->willReturn($aTokenResponse);

		$sDefaultScope="defaultScope";
		$this->oAdapterService->expects($this->once())
			->method('GetDefaultScope')
			->willReturn($sDefaultScope);

		$this->oOauth2ClientService->expects($this->once())
			->method('SaveTokens')
			->with($aTokenResponse, $sDefaultScope);

		$sAccessToken = 'token123';
		$this->oOauth2ClientService->expects($this->once())
			->method('GetAccessToken')
			->willReturn($sAccessToken);

		$this->assertEquals($sAccessToken, Oauth2Service::GetInstance()->AuthenticateFinish());
	}

	public function testGetAccessTokenNoInitializedYet() {
		$obj = $this->CreateOauth2Client();
		$sName = $obj->Get('name');
		$sProvider = $obj->Get('provider');

		$this->oOauth2ClientService->expects($this->once())
			->method('InitClient')
			->with($sName, $sProvider);

		$this->oAdapterService->expects($this->once())
			->method('Init')
			->with($sName, $sProvider);
		Oauth2Service::GetInstance()->Init($sName, $sProvider);

		$this->oOauth2ClientService->expects($this->once())
			->method('GetAccessToken')
			->willReturn(null);

		$this->expectExceptionMessage("Oauth2 never initialized");
		Oauth2Service::GetInstance()->GetAccessToken();
	}

	public function testGetAccessToken_UpToDateToken() {
		$obj = $this->CreateOauth2Client();
		$sName = $obj->Get('name');
		$sProvider = $obj->Get('provider');

		$this->oOauth2ClientService->expects($this->once())
			->method('InitClient')
			->with($sName, $sProvider);

		$this->oAdapterService->expects($this->once())
			->method('Init')
			->with($sName, $sProvider);
		Oauth2Service::GetInstance()->Init($sName, $sProvider);

		$sToken = 'token123';
		$this->oOauth2ClientService->expects($this->once())
			->method('GetAccessToken')
			->willReturn($sToken);

		$this->oOauth2ClientService->expects($this->once())
			->method('IsExpired')
			->willReturn(false);

		$this->assertEquals($sToken, Oauth2Service::GetInstance()->GetAccessToken());
	}

	public function testGetAccessToken_ExpiredToken() {

		$obj = $this->CreateOauth2Client();
		$sName = $obj->Get('name');
		$sProvider = $obj->Get('provider');

		$this->oOauth2ClientService->expects($this->once())
			->method('InitClient')
			->with($sName, $sProvider);

		$this->oAdapterService->expects($this->once())
			->method('Init')
			->with($sName, $sProvider);
		Oauth2Service::GetInstance()->Init($sName, $sProvider);

		$this->oOauth2ClientService->expects($this->exactly(2))
			->method('GetAccessToken')
			->willReturnOnConsecutiveCalls('token123', 'token12345');

		$this->oOauth2ClientService->expects($this->once())
			->method('IsExpired')
			->willReturn(true);

		$aConfig = ["shadok => 'gabuzomeu"];
		$this->oOauth2ClientService->expects($this->exactly(1))
			->method('GetRefreshTokenConfiguration')
			->willReturn($aConfig);

		$aTokenResponse = ["a"=> "b"];
		$this->oAdapterService->expects($this->once())
			->method('RefreshToken')
			->willReturn($aTokenResponse);

		$sDefaultScope="defaultScope";
		$this->oAdapterService->expects($this->once())
			->method('GetDefaultScope')
			->willReturn($sDefaultScope);

		$this->oOauth2ClientService->expects($this->once())
			->method('SaveTokens')
			->with($aTokenResponse, $sDefaultScope);

		$this->assertEquals('token12345', Oauth2Service::GetInstance()->GetAccessToken());
	}

	public function testGetAccessTokenByOauth2Client_UpToDate() {
		$obj = $this->CreateOauth2Client();
		$sName = $obj->Get('name');
		$sProvider = $obj->Get('provider');

		$this->oOauth2ClientService->expects($this->never())
			->method('InitClient');

		$this->oOauth2ClientService->expects($this->once())
			->method('InitClientByOauth2Client')
			->with($obj);

		$this->oAdapterService->expects($this->once())
			->method('Init')
			->with($sName, $sProvider);

		$sToken = 'token123';
		$this->oOauth2ClientService->expects($this->once())
			->method('GetAccessToken')
			->willReturn($sToken);

		$this->oOauth2ClientService->expects($this->once())
			->method('IsExpired')
			->willReturn(false);

		$this->assertEquals($sToken, Oauth2Service::GetInstance()->GetAccessTokenByOauth2Client($obj));
	}
}
