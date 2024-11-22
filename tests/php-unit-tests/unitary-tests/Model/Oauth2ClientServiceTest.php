<?php

namespace Combodo\iTop\Oauth2Client\Test\Model;

use Combodo\iTop\Test\UnitTest\ItopDataTestCase;

class Oauth2ClientServiceTest extends ItopDataTestCase {
	protected function setUp(): void {
		parent::setUp();
		$this->RequireOnceItopFile('env-production/combodo-oauth2-client/vendor/autoload.php');
	}

	protected function tearDown(): void {
		parent::tearDown();
	}
}
