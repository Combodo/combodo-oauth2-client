<?php

namespace Combodo\iTop\Oauth2Client\Test\Service;

use Combodo\iTop\Test\UnitTest\ItopDataTestCase;
use Oauth2Client;

class Oauth2ServiceTest extends ItopDataTestCase {
	protected function setUp(): void {
		parent::setUp();
		$this->RequireOnceItopFile('env-production/combodo-oauth2-client/vendor/autoload.php');
	}

	protected function tearDown(): void {
		parent::tearDown();
	}
}
