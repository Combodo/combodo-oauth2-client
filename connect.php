<?php
/**
 * @copyright   Copyright (C) 2010-2024 Combodo SAS
 * @license     https://www.combodo.com/documentation/combodo-software-license.html
 *
 */

namespace Combodo\iTop\HybridAuth;

use Combodo\iTop\Oauth2Client\Helper\Oauth2ClientException;
use Combodo\iTop\Oauth2Client\Helper\Oauth2ClientLog;
use Combodo\iTop\Oauth2Client\Service\Oauth2ClientService;
use Hybridauth\Hybridauth;
use Hybridauth\Logger\Logger;

/**
 *  Return from OpenID Provider after a successful login
 */
require_once('../../approot.inc.php');
require_once (APPROOT.'bootstrap.inc.php');
require_once (APPROOT.'application/startup.inc.php');

try{
	$sName = \utils::ReadParam('name');
	$sProvider = base64_decode(\utils::ReadParam('provider'));
	Oauth2ClientService::GetInstance()->Connect($sName, $sProvider);
} catch(\Exception $e){
	throw new Oauth2ClientException($e);
	//already logged

}
