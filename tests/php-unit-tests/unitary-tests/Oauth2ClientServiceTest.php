<?php

namespace Combodo\iTop\MFATotp\Test;

use Combodo\iTop\Application\Helper\Session;
use Combodo\iTop\Oauth2Client\Service\Oauth2ClientService;
use Combodo\iTop\Test\UnitTest\ItopDataTestCase;
use GithubOauth2Client;
use MetaModel;

/**
 * @runClassInSeparateProcess Required because PHPUnit outputs something earlier, thus causing the headers to be sent
 */
class Oauth2ClientServiceTest extends ItopDataTestCase
{
	const USE_TRANSACTION = false;

	protected function setUp(): void {
		parent::setUp();
		Session::$bAllowCLI = true;

		$this->RequireOnceItopFile('env-production/combodo-oauth2-client/vendor/autoload.php');
	}

	protected function tearDown(): void
	{
		parent::tearDown();
		Session::$bAllowCLI = false;
	}

	/*public function testGetToken() {
		//session_start();
		//Session::$bAllowCLI = false;
		$this->assertNull(Session::$iSessionId);
		Session::Start();
		$this->assertNotNull(Session::$iSessionId);
		$_SERVER['REMOTE_ADDR'] = '1.2.3.4';

		$oGithubOauth2Client = MetaModel::GetObject(GithubOauth2Client::class, 4);
		$sToken = $oGithubOauth2Client->Get('access_token')->GetPassword();
		$this->assertEquals($sToken, Oauth2ClientService::GetInstance()->GetToken($oGithubOauth2Client));
	}*/
}