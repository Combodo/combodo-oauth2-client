<?php
/**
 * @copyright   Copyright (C) 2010-2024 Combodo SARL
 * @license     http://opensource.org/licenses/AGPL-3.0
 */


namespace Combodo\iTop\Oauth2Client\Controller;

use Combodo\iTop\Application\UI\Base\Component\Button\ButtonUIBlockFactory;
use Combodo\iTop\Application\UI\Base\Component\Toolbar\Toolbar;
use Combodo\iTop\Application\WebPage\WebPage;
use Combodo\iTop\Oauth2Client\Helper\Oauth2ClientHelper;
use Combodo\iTop\Application\TwigBase\Controller\Controller;
use Combodo\iTop\Oauth2Client\Model\ConfigService;
use MenuBlock;
use Oauth2Client;
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

	public static function GetButtons(Oauth2Client $oOauth2Client, WebPage $oPage) : array
	{
		$aTab = [
			'oauth2-client-connect' => [ 'label' => 'Connect', 'icon_classes' => 'fa fa-book', 'reset' => false ],
			'oauth2-client-reset-and-connect' => [ 'label' => 'Reset token and connect', 'icon_classes' => 'fas fa-eraser', 'reset' => true ],
		];

		$aButtons = [];
		foreach($aTab as $sId => $aData){
			$oOauthConnectButton = ButtonUIBlockFactory::MakeIconAction($aData['icon_classes'], $aData['label'], null, null, false, $sId);
			$aButtons[]=$oOauthConnectButton;

			// Prepare button callback
			$sOauthConnectCallbackName = 'OauthConnectCallback'.utils::Sanitize($oOauthConnectButton->GetId(), '', utils::ENUM_SANITIZATION_FILTER_VARIABLE_NAME);

			$oOauthConnectButton->SetOnClickJsCode($sOauthConnectCallbackName.'();');

			$sUrl = ConfigService::GetInstance()->GetConnectUrl($oOauth2Client, $aData['reset']);
			$oPage->add_script(
				<<<JS
const $sOauthConnectCallbackName = function() {
window.location.assign('$sUrl');
};
JS
			);
		}
		return $aButtons;
	}
}
