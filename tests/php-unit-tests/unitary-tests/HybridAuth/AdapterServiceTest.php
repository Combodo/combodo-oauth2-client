<?php

namespace Combodo\iTop\Oauth2Client\Test\HybridAuth;

use Combodo\iTop\Test\UnitTest\ItopDataTestCase;

class AdapterServiceTest extends ItopDataTestCase {
	protected function setUp(): void {
		parent::setUp();
		$this->RequireOnceItopFile('env-production/combodo-oauth2-client/vendor/autoload.php');
	}

	protected function tearDown(): void {
		parent::tearDown();
	}
}
