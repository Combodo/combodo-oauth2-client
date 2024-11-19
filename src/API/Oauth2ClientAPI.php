<?php

namespace Combodo\iTop\Oauth2Client\API;

use Combodo\iTop\Oauth2Client\Helper\Oauth2ClientLog;
use Combodo\iTop\Oauth2Client\Service\Oauth2ClientService;
use Oauth2Client;
use User;

/**
 * @api
 * @package iTopExtension
 */
class Oauth2ClientAPI {
	/** @var Oauth2ClientAPI */
	private static $oInstance;

	private function __construct()
	{
		Oauth2ClientLog::Enable();
	}

	public static function GetInstance(): Oauth2ClientAPI
	{
		if (!isset(static::$oInstance)) {
			static::$oInstance = new Oauth2ClientAPI();
		}

		return static::$oInstance;
	}

	/**
	 * Get up to date token.
	 * Note: if needed, refresh workflow is triggered first. in that case its data are actualized (ie token expiration date...)
	 *
	 * @api
	 *
	 *  @param \Oauth2Client $oOauth2Client
	 *
	 * @return string: access token
	 * @throws \Combodo\iTop\Oauth2Client\Helper\Oauth2ClientException
	 *
	 * @since 3.2.0
	 */
	public function GetToken(Oauth2Client $oOauth2Client): string
	{
		return Oauth2ClientService::GetInstance()->GetToken($oOauth2Client);
	}
}
