<?php
/**
 * @copyright   Copyright (C) 2010-2024 Combodo SARL
 * @license     http://opensource.org/licenses/AGPL-3.0
 */

namespace Combodo\iTop\Oauth2Client\Service;

use Combodo\iTop\Oauth2Client\Helper\Oauth2ClientLog;
use Combodo\iTop\Oauth2Client\Model\ConfigService;
use Hybridauth\Hybridauth;
use Hybridauth\Logger\Logger;

class Oauth2ClientService
{
	/** @var Oauth2ClientService */
	private static $oInstance;

	private function __construct()
	{
	}

	public static function GetInstance(): Oauth2ClientService
	{
		if (!isset(static::$oInstance)) {
			static::$oInstance = new Oauth2ClientService();
		}

		return static::$oInstance;
	}

	public function Connect(string $sName, string $sProvider)
	{
		Oauth2ClientLog::Info("Connect", null, [$sName, $sProvider]);
		$aConfig = ConfigService::GetInstance()->GetConfig($sName, $sProvider);
		Oauth2ClientLog::Info("Connect", null, $aConfig);
		$oLogger = new Logger(Logger::DEBUG, APPROOT.'log/hybridauth.log');
		$oHybridAuth = new Hybridauth($aConfig, null, null, $oLogger);
		$oHybridAuth->authenticate($sName);
	}
}