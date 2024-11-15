<?php
/**
 * @copyright   Copyright (C) 2010-2024 Combodo SARL
 * @license     http://opensource.org/licenses/AGPL-3.0
 */

namespace Combodo\iTop\Oauth2Client\Hook;

use Combodo\iTop\Application\UI\Base\Component\Field\FieldUIBlockFactory;
use Combodo\iTop\Application\UI\Base\Component\FieldSet\FieldSetUIBlockFactory;
use Combodo\iTop\Oauth2Client\Model\ConfigService;
use Dict;
use utils;
use WebPage;

class ApplicationUIExtension extends \AbstractApplicationUIExtension
{

	public function OnDisplayProperties($oObject, WebPage $oPage, $bEditMode = false)
	{
		if (!$bEditMode) {
			return;
		}
		$oFieldSet = FieldSetUIBlockFactory::MakeStandard(Dict::S('Oauth2Client:UI:IDPParameters'));

		$oField = FieldUIBlockFactory::MakeSmall(Dict::S('Oauth2Client:UI:AppURL'), utils::GetAbsoluteUrlAppRoot());
		$oFieldSet->AddSubBlock($oField);

		$oField = FieldUIBlockFactory::MakeSmall(Dict::S('Oauth2Client:UI:LandingURL'), ConfigService::GetInstance()->GetLandingURL());
		$oFieldSet->AddSubBlock($oField);

		$oPage->AddUiBlock($oFieldSet);
	}
}
