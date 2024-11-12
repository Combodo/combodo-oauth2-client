<?php
/**
 * @copyright   Copyright (C) 2010-2024 Combodo SAS
 * @license     https://www.combodo.com/documentation/combodo-software-license.html
 *
 */

namespace Combodo\iTop\Oauth2Client;

use Combodo\iTop\Application\Helper\Session;
use Combodo\iTop\Oauth2Client\Helper\Oauth2ClientException;
use Combodo\iTop\Oauth2Client\Helper\Oauth2ClientLog;
use Combodo\iTop\Oauth2Client\Service\Oauth2ClientService;
use Hybridauth\Logger\Logger;

/**
 *  Return from OpenID Provider after a successful login
 */
require_once('../../approot.inc.php');
require_once (APPROOT.'bootstrap.inc.php');
require_once (APPROOT.'application/startup.inc.php');

Oauth2ClientLog::Enable();
Oauth2ClientLog::Info('---------------------------------');
Oauth2ClientLog::Info($_SERVER['REQUEST_URI']);

Oauth2ClientLog::Info("--> Entering Oauth2 landing page");
$sSessionLog = session_id() . ' ' . \utils::GetSessionLog();
Oauth2ClientLog::Info("SESSION: $sSessionLog");

try{
	$sName = Session::Get('oauth2_client_name');
	$sProvider = Session::Get('oauth2_client_provider');

	/** @var \Hybridauth\Adapter\AdapterInterface $oAdapter */
	$oAdapter = Oauth2ClientService::GetInstance()->StoreTokens($sName, $sProvider);
	echo json_encode($oAdapter->getUserProfile(), JSON_PRETTY_PRINT);
} catch(\Exception $e){
	throw new Oauth2ClientException($e);

}
