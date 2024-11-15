<?php
/**
 * @copyright   Copyright (C) 2010-2024 Combodo SARL
 * @license     http://opensource.org/licenses/AGPL-3.0
 */

namespace Combodo\iTop\Oauth2Client\Test;

use Combodo\iTop\Oauth2Client\Model\ConfigService;
use Combodo\iTop\Oauth2Client\Service\HybridAuthService;
use Combodo\iTop\Test\UnitTest\ItopDataTestCase;
use Hybridauth\Adapter\OAuth2;
use Oauth2Client;
use Combodo\iTop\Application\Helper\Session;

/**
 * @runClassInSeparateProcess Required because PHPUnit outputs something earlier, thus causing the headers to be sent
 */
class HybridAuthServiceTest extends ItopDataTestCase
{
	protected function setUp(): void {
		parent::setUp();
		Session::$bAllowCLI = false;

		$this->RequireOnceItopFile('env-production/combodo-oauth2-client/vendor/autoload.php');
	}

	protected function tearDown(): void {
		parent::tearDown();
		//Session::$bAllowCLI = true;
	}

	public function ProvidersReturnedProvider()
	{
		return [
			[ 'GitHub' ],
			[ 'MicrosoftGraph' ],
			[ 'Google' ],
		];

	}

	/**
	 * @dataProvider ProvidersReturnedProvider
	 */
	public function testProvidersReturned(string $sProviderName)
	{
		Session::Start();
		$_SERVER['REMOTE_ADDR'] = '1.2.3.4';
		$oOauth2Client = $this->CreateOauth2client("{$sProviderName}Oauth2Client");
		$oOauth2ClientCompleted = ConfigService::GetInstance()->GetOauth2Client('webhook', $oOauth2Client->Get('provider'));
		$this->assertEquals("Hybridauth\\Provider\\$sProviderName", get_class($oOauth2ClientCompleted->GetOauth2()));
	}

	private function CreateOauth2client($sOauth2ClientClass) : Oauth2Client
	{
		$aFields = [
			"name" => 'webhook',
			'client_id' => 'client_123',
			'client_secret' => 'secret456',
			'scope' => 'toto',
			'access_token' => 'access_token1',
			'token_type' => 'token_type1',
			'refresh_token' => 'refresh_token1',
			'access_token_expiration' => '2024-11-12 00:37:48',
		];

		/** @var Oauth2Client $oOauth2Client */
		$oOauth2Client = $this->createObject($sOauth2ClientClass,
			$aFields
		);

		return $oOauth2Client;
	}

}
