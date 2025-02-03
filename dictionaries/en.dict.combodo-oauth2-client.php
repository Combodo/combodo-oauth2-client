<?php
/**
 * @copyright   Copyright (C) 2010-2024 Combodo SARL
 * @license     http://opensource.org/licenses/AGPL-3.0
 */

/**
 * Localized data
 */

Dict::Add('EN US', 'English', 'English', [
	'Oauth2Client:UI:IDPParameters' => 'Data for the Identity Provider',
	'Oauth2Client:UI:AppURL' => 'Application URL',
	'Oauth2Client:UI:LandingURL' => 'Landing URL',

	'Oauth2Client:UI:Message:ValidationOK' => 'Validation OK:<BR/>%1$s',
	'Oauth2Client:UI:Message:ValidationError' => 'Failed validating token: %1$s',

	'Oauth2Client:UI:Button:GetToken' => 'Display access token. If expired, access token is refreshed before via Oauth.',
	'Oauth2Client:UI:Button:Authenticate' => 'Authenticate to the IDP via Oauth.',

	'Oauth2Client:UI:Error:RefreshTokenNotAvailable' => 'Refresh token not available',

	'Menu:Oauth2Client' => 'OAuth 2.0 client',
	'Menu:Oauth2Client+' => 'General purpose OAuth 2.0 Client',

	'Class:Oauth2Client' => 'OAuth 2.0 client',
	'Class:Oauth2Client/Attribute:name' => 'Name',
	'Class:Oauth2Client/Attribute:provider' => 'Provider',
	'Class:Oauth2Client/Attribute:client_id' => 'Client id',
	'Class:Oauth2Client/Attribute:client_secret' => 'Client Secret',
	'Class:Oauth2Client/Attribute:refresh_token' => 'Refresh Token',
	'Class:Oauth2Client/Attribute:access_token' => 'Access Token',
	'Class:Oauth2Client/Attribute:refresh_token_expiration' => 'Refresh Token Expiration',
	'Class:Oauth2Client/Attribute:access_token_expiration' => 'Access Token Expiration',
	'Class:Oauth2Client/Attribute:scope' => 'Scope',
	'Class:Oauth2Client/Attribute:scope+' => 'Leave this field empty and it will be filled by iTop based on the provider when creating the object',
	'Class:Oauth2Client/Attribute:authorization_state' => 'Authorization State',
	'Class:Oauth2Client/Attribute:status' => 'Status',
	'Class:Oauth2Client/Attribute:token_type' => 'Token Type',

	'Class:GitHubOauth2Client' => 'GitHub OAuth 2.0 client',

	'Class:MicrosoftGraphOauth2Client' => 'Microsoft Graph OAuth 2.0 client',
	'Class:MicrosoftGraphOauth2Client/Attribute:tenant' => 'Tenant',

	'Class:GoogleOauth2Client' => 'Google OAuth 2.0 client',

	'Class:HeadlessOauth2Client' => 'Headless OAuth 2.0 client',
	'Class:HeadlessOauth2Client/Attribute:username' => 'Username',
	'Class:HeadlessOauth2Client/Attribute:password' => 'Password',
	'Class:HeadlessOauth2Client/Attribute:base_url' => 'Base URL',
	'Class:HeadlessOauth2Client/Attribute:version' => 'Version',

	'Class:KeycloakOauth2Client' => 'Keycloak OAuth 2.0 client',
	'Class:KeycloakOauth2Client/Attribute:url' => 'URL',
	'Class:KeycloakOauth2Client/Attribute:realm' => 'Realm',

	'OAuth2Client:baseinfo' => 'Purpose',
	'OAuth2Client:idp_info' => 'Data from Identity Provider',
]);
