<?php
/**
 * @copyright   Copyright (C) 2010-2024 Combodo SARL
 * @license     http://opensource.org/licenses/AGPL-3.0
 */


namespace Combodo\iTop\Oauth2Client\Controller;

use Combodo\iTop\Oauth2Client\Helper\Oauth2ClientHelper;
use Combodo\iTop\Application\TwigBase\Controller\Controller;
use utils;

class Oauth2ClientController extends Controller
{
	public function OperationDefault()
	{
		$aParams = [];

		$this->AddLinkedStylesheet(utils::GetAbsoluteUrlModulesRoot().Oauth2ClientHelper::MODULE_NAME.'/assets/css/Oauth2Client.css');
		$this->AddLinkedScript(utils::GetAbsoluteUrlModulesRoot().Oauth2ClientHelper::MODULE_NAME.'/assets/js/Oauth2Client.js');
		$this->DisplayPage($aParams);
	}
}