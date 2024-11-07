<?php
/**
 * @copyright   Copyright (C) 2010-2024 Combodo SARL
 * @license     http://opensource.org/licenses/AGPL-3.0
 */

namespace Combodo\iTop\Oauth2Client;

use Combodo\iTop\Oauth2Client\Controller\Oauth2ClientController;
use Combodo\iTop\Oauth2Client\Helper\Oauth2ClientHelper;

require_once(APPROOT.'application/startup.inc.php');

$oController = new Oauth2ClientController(MODULESROOT.Oauth2ClientHelper::MODULE_NAME.'/templates', Oauth2ClientHelper::MODULE_NAME);
$oController->SetDefaultOperation('Default');
$oController->HandleOperation();