<?php
/**
 * @copyright   Copyright (C) 2010-2024 Combodo SAS
 * @license     https://www.combodo.com/documentation/combodo-software-license.html
 *
 */

namespace Combodo\iTop\Oauth2Client;

use Combodo\iTop\Application\Helper\Session;
use Combodo\iTop\Oauth2Client\Helper\Oauth2ClientException;
use Combodo\iTop\Oauth2Client\Service\Oauth2ClientService;

/**
 *  Return from OpenID Provider after a successful login
 */
require_once('../../approot.inc.php');
require_once (APPROOT.'bootstrap.inc.php');
require_once (APPROOT.'application/startup.inc.php');

try{
	$sName = \utils::ReadParam('name');
	$sProvider = base64_decode(\utils::ReadParam('provider'));
	Session::Set('oauth2_client_name', $sName);
	Session::Set('oauth2_client_provider', $sProvider);

	/** @var \Hybridauth\Adapter\AdapterInterface $oAdapter */
	$oAdapter = Oauth2ClientService::GetInstance()->Connect($sName, $sProvider);
	$sJson = json_encode($oAdapter->getUserProfile(), JSON_PRETTY_PRINT);

	$sHTML = <<<HTML
<pre>
$sJson
</pre>
HTML;
	echo $sHTML;
} catch(\Exception $e){
	throw new Oauth2ClientException($e);
	//already logged

}
