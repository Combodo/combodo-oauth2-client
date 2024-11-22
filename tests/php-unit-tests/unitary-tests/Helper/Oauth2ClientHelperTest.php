<?php

namespace Combodo\iTop\Oauth2Client\Test\HybridAuth;

use Combodo\iTop\Oauth2Client\Helper\Oauth2ClientHelper;
use Combodo\iTop\Test\UnitTest\ItopDataTestCase;

class Oauth2ClientHelperTest extends ItopDataTestCase {
	protected function setUp(): void {
		parent::setUp();
		$this->RequireOnceItopFile('env-production/combodo-oauth2-client/vendor/autoload.php');
	}

	protected function tearDown(): void {
		parent::tearDown();
	}

	public function GetConnectUrlProvider() {
		return [
			'reset with GitHub' => [ 'class' => \GitHubOauth2Client::class, 'action' => 'authenticate' ],
			'NO reset with MS' => [ 'class' => \MicrosoftGraphOauth2Client::class, 'action' => 'resfresh_token' ],
		];
	}

	/**
	 * @dataProvider GetConnectUrlProvider
	 */
	public function testGetConnectUrl(string $sClass, string $sAction) {
		$oOauth2Client = $this->createObject($sClass,
			['name' => 'testname', 'client_id' => 'sClientId', 'client_secret' => 'sClientSecret']
		);

		$sProvider = $oOauth2Client->Get('provider');
		$sProvider = urlencode(base64_encode($sProvider));
		$sUrl = Oauth2ClientHelper::GetConnectUrl('testname', $sProvider, $sAction);
		$sExpectedUrl = \utils::GetAbsoluteUrlModulesRoot().Oauth2ClientHelper::MODULE_NAME."/connect.php?name=testname&provider=$sProvider&action=$sAction";

		$this->assertEquals($sExpectedUrl, $sUrl);
	}
}
