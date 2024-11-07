<?php
/**
 * @copyright   Copyright (C) 2010-2024 Combodo SARL
 * @license     http://opensource.org/licenses/AGPL-3.0
 */

namespace Combodo\iTop\Oauth2Client\Helper;

use LogAPI;

class Oauth2ClientLog extends LogAPI
{
	const CHANNEL_DEFAULT = 'Oauth2ClientLog';

	protected static $m_oFileLog = null;
}