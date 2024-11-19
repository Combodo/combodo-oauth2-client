<?php
/**
 * @copyright   Copyright (C) 2010-2024 Combodo SAS
 * @license     https://www.combodo.com/documentation/combodo-software-license.html
 *
 */

namespace Combodo\iTop\Oauth2Client;

use Combodo\iTop\Application\Helper\Session;
use Combodo\iTop\Application\WebPage\WebPage;
use Combodo\iTop\Oauth2Client\Controller\Oauth2ClientController;
use Combodo\iTop\Oauth2Client\Helper\Oauth2ClientException;
use Combodo\iTop\Oauth2Client\Model\ConfigService;
use Combodo\iTop\Oauth2Client\Service\Oauth2ClientService;
use iTopStandardURLMaker;

/**
 *  Return from OpenID Provider after a successful login
 */
require_once('../../approot.inc.php');
require_once (APPROOT.'bootstrap.inc.php');
require_once (APPROOT.'application/startup.inc.php');

try{
	$sName = \utils::ReadParam('name');
	$sProvider = base64_decode(\utils::ReadParam('provider'));
	$sAction = \utils::ReadParam('action');
	Session::Set('oauth2_client_name', $sName);
	Session::Set('oauth2_client_provider', $sProvider);

	$oOauth2Client = ConfigService::GetInstance()->GetOauth2Client($sName, $sProvider);
	Oauth2ClientService::GetInstance()->Connect($sName, $sProvider, $sAction === Oauth2ClientController::ACTION_RESET);

	$oOauth2Client::SetSessionMessage(get_class($oOauth2Client), $oOauth2Client->GetKey(), 1, "Action $sAction OK", WebPage::ENUM_SESSION_MESSAGE_SEVERITY_OK, 1);

} catch (Oauth2ClientException $e) {
	if (! is_null($oOauth2Client)){
		$oOauth2Client::SetSessionMessage(get_class($oOauth2Client), $oOauth2Client->GetKey(), 1, "Failed validating token: " . $e->getMessage(), WebPage::ENUM_SESSION_MESSAGE_SEVERITY_ERROR, 1);
	}
} catch (\Exception $e) {
	//exception instanciated to generate log.
	$e = new Oauth2ClientException(__FUNCTION__.': failed', 0, $e);
	if (! is_null($oOauth2Client)){
		$oOauth2Client::SetSessionMessage(get_class($oOauth2Client), $oOauth2Client->GetKey(), 1, "Failed validating token: " . $e->getMessage(), WebPage::ENUM_SESSION_MESSAGE_SEVERITY_ERROR, 1);
	}
}

if (! is_null($oOauth2Client)) {
	$sUrl = iTopStandardURLMaker::MakeObjectURL(get_class($oOauth2Client), $oOauth2Client->GetKey());
	header('HTTP/1.1 307 Temporary Redirect');
	header("Location: $sUrl");
}
