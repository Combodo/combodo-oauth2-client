<?php
/**
 * @copyright   Copyright (C) 2010-2024 Combodo SAS
 * @license     https://www.combodo.com/documentation/combodo-software-license.html
 *
 */

namespace Combodo\iTop\HybridAuth;

use Combodo\iTop\Oauth2Client\Helper\Oauth2ClientLog;
use Hybridauth\Hybridauth;
use Hybridauth\Logger\Logger;

/**
 *  Return from OpenID Provider after a successful login
 */
require_once('../../approot.inc.php');
require_once (APPROOT.'bootstrap.inc.php');
require_once (APPROOT.'application/startup.inc.php');

Oauth2ClientLog::Info('---------------------------------');
Oauth2ClientLog::Info($_SERVER['REQUEST_URI']);

try{
	$oLogger = new Logger(Logger::DEBUG, APPROOT.'log/hybridauth.log');

	//$sOauth2ClientClass =
	//$sObjectId = ;


	Combodo\iTop\Oauth2Client\Service\Oauth2ClientService::GetInstance()->Connect($sName, $sProvider);
	//$oHybridAuth = new Hybridauth($aConfig, null, null, $oLogger);
	//$oAuthAdapter = $oHybridAuth->authenticate($sName);
} catch(\Exception $e){
	//already logged

}
