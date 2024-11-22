<?php

namespace Combodo\iTop\Oauth2Client\HybridAuth;

use Hybridauth\Adapter\AdapterInterface;
use Hybridauth\Hybridauth;
use Hybridauth\Logger\Logger;

class AdapterFabrikService {
	private static ?AdapterFabrikService $oInstance;

	protected function __construct() {
	}

	final public static function GetInstance(): AdapterFabrikService {
		if (!isset(static::$oInstance)) {
			static::$oInstance = new static();
		}

		return static::$oInstance;
	}

	final public static function SetInstance(?AdapterFabrikService $oInstance): void {
		static::$oInstance = $oInstance;
	}

	public function GetAdapterInterface($sProviderName, array $aConfig, Logger $oLogger) : AdapterInterface
	{
		$oHybridauth = new Hybridauth($aConfig, null, null, $oLogger);
		return $oHybridauth->getAdapter($sProviderName);
	}
}
