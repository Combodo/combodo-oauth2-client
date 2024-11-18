<?php
/**
 * @copyright   Copyright (C) 2010-2024 Combodo SARL
 * @license     http://opensource.org/licenses/AGPL-3.0
 */

namespace Combodo\iTop\Oauth2Client\Helper;

use Exception;
use Throwable;

class Oauth2ClientException extends Exception
{
	public function __construct(string $message = "", int $code = 0, ?Throwable $previous = null, array $aContext = [])
	{
		if (!is_null($previous)) {
			$sStack = $previous->getTraceAsString();
			$sError = $previous->getMessage();
		} else {
			$sStack = $this->getTraceAsString();
			$sError = '';
		}

		$aContext['error'] = $sError;
		$aContext['stack'] = $sStack;
		Oauth2ClientLog::Error($message, null, $aContext);
		parent::__construct($message, $code, $previous);
	}
}