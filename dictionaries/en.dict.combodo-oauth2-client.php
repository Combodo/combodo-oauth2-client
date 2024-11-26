<?php
/**
 * @copyright   Copyright (C) 2010-2024 Combodo SARL
 * @license     http://opensource.org/licenses/AGPL-3.0
 */

/**
 * Localized data
 */

Dict::Add('EN US', 'English', 'English', [
	'Oauth2Client:UI:IDPParameters' => 'IDP Parameters',
	'Oauth2Client:UI:AppURL' => 'Application URL',
	'Oauth2Client:UI:LandingURL' => 'Landing URL',

	'Oauth2Client:UI:Message:ValidationOK' => 'Validation OK:<BR/>%1$s',
	'Oauth2Client:UI:Message:ValidationError' => 'Failed validating token: %1$s',

	'Oauth2Client:UI:Button:GetToken' => 'Display access token. If expired, access token is refreshed before via Oauth.',
	'Oauth2Client:UI:Button:Authenticate' => 'Authenticate to the IDP via Oauth.',

	'Oauth2Client:UI:Error:RefreshTokenNotAvailable' => 'Refresh token not available',

	'Menu:Oauth2Client' => 'OAuth 2.0 client',
	'Menu:Oauth2Client+' => 'General purpose OAuth 2.0 Client',
]);
