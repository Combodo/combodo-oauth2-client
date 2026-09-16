<?php
/**
 * @copyright   Copyright (C) 2010-2026 Combodo SARL
 * @license     http://opensource.org/licenses/AGPL-3.0
 */

/**
 * Localized data
 */

Dict::Add('DE DE', 'German', 'Deutsch', [
	'Oauth2Client:UI:IDPParameters' => 'Daten für den Identity Provider',
	'Oauth2Client:UI:AppURL' => 'Anwendungs-URL',
	'Oauth2Client:UI:AppURL+' => 'Diese URL muss in die OAuth2-Konfiguration des Providers übernommen werden',
	'Oauth2Client:UI:LandingURL' => 'Landing-URL',
	'Oauth2Client:UI:LandingURL+' => 'Diese URL muss in die OAuth2-Konfiguration des Providers übernommen werden',

	'Oauth2Client:UI:Message:ValidationOK' => 'Validierung erfolgreich:<BR/>%1$s',
	'Oauth2Client:UI:Message:ValidationError' => 'Validierung des Tokens fehlgeschlagen: %1$s',

	'Oauth2Client:UI:Button:GetToken' => 'Access Token anzeigen. Ist es abgelaufen, wird es zuvor per OAuth erneuert.',
	'Oauth2Client:UI:Button:Authenticate' => 'Per OAuth am IdP authentifizieren.',

	'Oauth2Client:UI:Error:RefreshTokenNotAvailable' => 'Refresh Token nicht verfügbar',

	'Menu:Oauth2Client' => 'OAuth-2.0-Client',
	'Menu:Oauth2Client+' => 'Universeller OAuth-2.0-Client',

	'Class:Oauth2Client' => 'OAuth-2.0-Client',
	'Class:Oauth2Client/Attribute:name' => 'Name',
	'Class:Oauth2Client/Attribute:name+' => '',
	'Class:Oauth2Client/Attribute:provider' => 'Provider',
	'Class:Oauth2Client/Attribute:provider+' => '',
	'Class:Oauth2Client/Attribute:description' => 'Beschreibung',
	'Class:Oauth2Client/Attribute:description+' => '',
	'Class:Oauth2Client/Attribute:client_id' => 'Client-ID',
	'Class:Oauth2Client/Attribute:client_id+' => 'Eine lange Zeichenkette, die Ihr OAuth2-Provider bereitstellt',
	'Class:Oauth2Client/Attribute:client_secret' => 'Client Secret',
	'Class:Oauth2Client/Attribute:client_secret+' => 'Eine weitere lange Zeichenkette, die Ihr OAuth2-Provider bereitstellt',
	'Class:Oauth2Client/Attribute:refresh_token' => 'Refresh Token',
	'Class:Oauth2Client/Attribute:refresh_token+' => 'Token, das zum automatischen Erneuern des Access Tokens benötigt wird',
	'Class:Oauth2Client/Attribute:access_token' => 'Access Token',
	'Class:Oauth2Client/Attribute:access_token+' => 'Token, das zum Aufruf entfernter OAuth2-APIs benötigt wird',
	'Class:Oauth2Client/Attribute:refresh_token_expiration' => 'Ablauf des Refresh Tokens',
	'Class:Oauth2Client/Attribute:refresh_token_expiration+' => 'Ablaufdatum, nach dem abgelaufene Access Tokens nicht mehr erneuert werden können. Sie müssen den aktuellen OAuth-2.0-Client dann erneut bei Ihrem Identity Provider validieren',
	'Class:Oauth2Client/Attribute:access_token_expiration' => 'Ablauf des Access Tokens',
	'Class:Oauth2Client/Attribute:access_token_expiration+' => 'Ablaufdatum des Access Tokens, nach dem die OAuth2-APIs nicht mehr aufgerufen werden können. Nach diesem Datum erneuert iTop das Access Token nach Möglichkeit automatisch über einen OAuth2-Austausch und stellt ein gültiges Token bereit.',
	'Class:Oauth2Client/Attribute:scope' => 'Scope',
	'Class:Oauth2Client/Attribute:scope+' => 'Lassen Sie dieses Feld leer, iTop füllt es beim Anlegen des Objekts anhand des Providers',
	'Class:Oauth2Client/Attribute:authorization_state' => 'Autorisierungsstatus',
	'Class:Oauth2Client/Attribute:authorization_state+' => '',
	'Class:Oauth2Client/Attribute:token_type' => 'Token-Typ',
	'Class:Oauth2Client/Attribute:token_type+' => '',

	'Class:GitHubOauth2Client' => 'GitHub OAuth-2.0-Client',

	'Class:MicrosoftGraphOauth2Client' => 'Microsoft Graph OAuth-2.0-Client',
	'Class:MicrosoftGraphOauth2Client/Attribute:tenant' => 'Tenant',
	'Class:MicrosoftGraphOauth2Client/Attribute:tenant+' => 'Tenant-ID der konfigurierten Anwendung. Für mandantenübergreifende Anwendungen "common" verwenden.',

	'Class:GoogleOauth2Client' => 'Google OAuth-2.0-Client',

	'Class:HeadlessOauth2Client' => 'Headless OAuth-2.0-Client',
	'Class:HeadlessOauth2Client/Attribute:username' => 'Benutzername',
	'Class:HeadlessOauth2Client/Attribute:username+' => 'iTop-Benutzerkennung',
	'Class:HeadlessOauth2Client/Attribute:password' => 'Passwort',
	'Class:HeadlessOauth2Client/Attribute:password+' => 'Passwort des iTop-Benutzers',
	'Class:HeadlessOauth2Client/Attribute:base_url' => 'Basis-URL',
	'Class:HeadlessOauth2Client/Attribute:base_url+' => 'URL der iTop-Anwendung.',
	'Class:HeadlessOauth2Client/Attribute:version' => 'Version',
	'Class:HeadlessOauth2Client/Attribute:version+' => '',

	'Class:KeycloakOauth2Client' => 'Keycloak OAuth-2.0-Client',
	'Class:KeycloakOauth2Client/Attribute:url' => 'URL',
	'Class:KeycloakOauth2Client/Attribute:url+' => 'URL der Keycloak-Anwendung.',
	'Class:KeycloakOauth2Client/Attribute:realm' => 'Realm',
	'Class:KeycloakOauth2Client/Attribute:realm+' => 'Realm der konfigurierten Anwendung.',

	'OAuth2Client:baseinfo' => 'Zweck',
	'OAuth2Client:idp_info' => 'Daten vom Identity Provider',
]);
