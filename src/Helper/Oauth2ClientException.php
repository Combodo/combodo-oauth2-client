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
	public function __construct($message = '', $code = 0, Throwable $previous = null)
	{
		parent::__construct(Oauth2ClientHelper::MODULE_NAME.': '.$message, $code, $previous);
	}
}