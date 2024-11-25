<?php
/**
 * @copyright   Copyright (C) 2010-2024 Combodo SARL
 * @license     http://opensource.org/licenses/AGPL-3.0
 */


namespace Combodo\iTop\Oauth2Client\Controller;

use Combodo\iTop\Application\TwigBase\Controller\Controller;
use Combodo\iTop\Application\UI\Base\Component\Button\ButtonUIBlockFactory;
use Combodo\iTop\Application\WebPage\WebPage;
use Combodo\iTop\Oauth2Client\Helper\Oauth2ClientHelper;
use Oauth2Client;
use utils;

class Oauth2ClientController extends Controller
{
	public const ACTION_AUTHENTICATE = 'authenticate';
	public const ACTION_GET_TOKEN = 'get_token';

	public function OperationDefault()
	{
		$aParams = [];

		$this->AddLinkedStylesheet(utils::GetAbsoluteUrlModulesRoot().Oauth2ClientHelper::MODULE_NAME.'/assets/css/Oauth2Client.css');
		$this->AddLinkedScript(utils::GetAbsoluteUrlModulesRoot().Oauth2ClientHelper::MODULE_NAME.'/assets/js/Oauth2Client.js');
		$this->DisplayPage($aParams);
	}

	public static function GetButtons(Oauth2Client $oOauth2Client, WebPage $oPage): array
	{
		$aTab = [
			'oauth2-client-get-token' => [
				'label' => 'Oauth2Client:UI:Button:GetToken',
				'icon_classes' => 'fas fa-check-circle',
				'action' => self::ACTION_GET_TOKEN
			],
			'oauth2-client-reset-and-connect' => [
				'label' => 'Oauth2Client:UI:Button:Authenticate',
				'icon_classes' => 'fas fa-user-check',
				'action' => self::ACTION_AUTHENTICATE
			],
		];

		$aButtons = [];
		foreach ($aTab as $sId => $aData) {
			$oOauthConnectButton = ButtonUIBlockFactory::MakeIconAction($aData['icon_classes'], \Dict::S($aData['label']), null, null, false, $sId);
			$aButtons[] = $oOauthConnectButton;

			// Prepare button callback
			$sOauthConnectCallbackName = 'OauthConnectCallback'.utils::Sanitize($oOauthConnectButton->GetId(), '', utils::ENUM_SANITIZATION_FILTER_VARIABLE_NAME);

			$oOauthConnectButton->SetOnClickJsCode($sOauthConnectCallbackName.'();');

			$sName = $oOauth2Client->Get('name');
			$sProvider = $oOauth2Client->Get('provider');
			$sUrl = Oauth2ClientHelper::GetConnectUrl($sName, $sProvider, $aData['action']);
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
