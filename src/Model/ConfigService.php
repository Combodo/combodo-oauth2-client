<?php
/**
 * @copyright   Copyright (C) 2010-2024 Combodo SARL
 * @license     http://opensource.org/licenses/AGPL-3.0
 */

namespace Combodo\iTop\Oauth2Client\Model;

use Combodo\iTop\Oauth2Client\Helper\Oauth2ClientException;
use Combodo\iTop\Oauth2Client\Helper\Oauth2ClientLog;
use Hybridauth\Logger\Logger;

class ConfigService
{
	/** @var ConfigService */
	private static $oInstance;

	private function __construct()
	{
	}

	public static function GetInstance(): ConfigService
	{
		if (!isset(static::$oInstance)) {
			static::$oInstance = new ConfigService();
		}

		return static::$oInstance;
	}

	public function GetConfig(string $sName, string $sProvider) : array
	{
		\IssueLog::Error("GetConfig", null, [$sName, $sProvider]);
		$oSearch = \DBSearch::FromOQL("SELECT Oauth2Client WHERE name=:name AND provider=:provider");
		$oSet = new \DBObjectSet($oSearch, [], ['name' => $sName, 'provider' => $sProvider]);
		if ($oSet->Count() != 1){
			throw new Oauth2ClientException("Missing configuration", 0, null, ['name' => $sName, 'provider' => $sProvider]);
		}

		$aData = $oSet->FetchAssoc();
		$aData['adapter'] = 'Hybridauth\Provider\Github';

		$aRes = [$sName => $aData];

		\IssueLog::Error("GetConfig", null, [$sName, $sProvider, $aRes]);
		return $aRes;
	}
}