<?php

namespace Combodo\iTop\Oauth2Client\HybridAuth;

use Combodo\iTop\Oauth2Client\Helper\Oauth2ClientLog;
use Hybridauth\Adapter\AdapterInterface;
use Hybridauth\Hybridauth;
use Hybridauth\Logger\Logger;

class AdapterInterfaceFactoryService {
	private static ?AdapterInterfaceFactoryService $oInstance;

	protected function __construct() {
	}

	final public static function GetInstance(): AdapterInterfaceFactoryService {
		if (!isset(static::$oInstance)) {
			static::$oInstance = new static();
		}

		return static::$oInstance;
	}

	final public static function SetInstance(?AdapterInterfaceFactoryService $oInstance): void {
		static::$oInstance = $oInstance;
	}

	public function GetAdapterInterface($sProviderName, array $aConfig, Logger $oLogger=null) : AdapterInterface
	{
		if (is_null($oLogger)){
			$oLogger = new Logger(Oauth2ClientLog::GetHybridauthDebugMode(), APPROOT.'log/hybridauth.log');
		}
		$oHybridauth = new Hybridauth($aConfig, null, null, $oLogger);
		return $oHybridauth->getAdapter($sProviderName);
	}
}
