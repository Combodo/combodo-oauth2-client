<?php
/**
 * @copyright   Copyright (C) 2010-2024 Combodo SARL
 * @license     http://opensource.org/licenses/AGPL-3.0
 */

 /**
 * Localized data
 */

Dict::Add('FR FR', 'French', 'Français', [
	'Oauth2Client:UI:IDPParameters' => 'Paramètres de l\'IdP',
	'Oauth2Client:UI:AppURL' => 'URL de l\'application',
	'Oauth2Client:UI:LandingURL' => 'URL de retour',

	'Oauth2Client:UI:Message:ValidationOK' => 'Jeton valide :<BR/>%1$s',
	'Oauth2Client:UI:Message:ValidationError' => 'Le jeton n\'a pas été validé : %1$s',

	'Oauth2Client:UI:Button:GetToken' => 'Affiche le jeton d\'accès. Le jeton est régénéré si nécessaire',
	'Oauth2Client:UI:Button:Authenticate' => 'Authentification sur l\'IdP',

	'Oauth2Client:UI:Error:RefreshTokenNotAvailable' => 'Le jeton de rafraichissement n\'est pas disponible',

	'Menu:Oauth2Client' => 'Client OAuth 2.0',
	'Menu:Oauth2Client+' => 'Client OAuth 2.0 générique',

	'Class:Oauth2Client' => 'Client OAuth 2.0',
	'Class:Oauth2Client/Attribute:name' => 'Nom',
	'Class:Oauth2Client/Attribute:provider' => 'Fournisseur',
	'Class:Oauth2Client/Attribute:client_id' => 'ID du Client',
	'Class:Oauth2Client/Attribute:client_secret' => 'Secret du Client',
	'Class:Oauth2Client/Attribute:refresh_token' => 'Jeton de rafraîchissement',
	'Class:Oauth2Client/Attribute:access_token' => 'Jeton d\'accès',
	'Class:Oauth2Client/Attribute:refresh_token_expiration' => 'Expiration du Jeton de rafraîchissement',
	'Class:Oauth2Client/Attribute:access_token_expiration' => 'Expiration du Jeton d\'accès',
	'Class:Oauth2Client/Attribute:scope' => 'Scope',
	'Class:Oauth2Client/Attribute:scope+' => 'A la création de l\'objet, le scope, s\'il est laissé vide, est rempli automatiquement selon le fournisseur',
	'Class:Oauth2Client/Attribute:authorization_state' => 'Statut d\'Autorisation State',
	'Class:Oauth2Client/Attribute:status' => 'Statut',
	'Class:Oauth2Client/Attribute:token_type' => 'Type de Token',

	'Class:GitHubOauth2Client' => 'Client OAuth 2.0 GitHub',

	'Class:MicrosoftGraphOauth2Client' => 'Client OAuth 2.0 Microsoft Graph',
	'Class:MicrosoftGraphOauth2Client/Attribute:tenant' => 'Tenant',

	'Class:GoogleOauth2Client' => 'Client OAuth 2.0 Google',

	'Class:HeadlessItopOauth2Client' => 'Client OAuth 2.0 Headless',
	'Class:HeadlessItopOauth2Client/Attribute:username' => 'Nom d\'utilisateur',
	'Class:HeadlessItopOauth2Client/Attribute:password' => 'Mot de Passe',
	'Class:HeadlessItopOauth2Client/Attribute:base_url' => 'URL de Base',
	'Class:HeadlessItopOauth2Client/Attribute:version' => 'Version',

	'Class:KeycloakOauth2Client' => 'Client OAuth 2.0 Keycloak',
	'Class:KeycloakOauth2Client/Attribute:url' => 'URL',
	'Class:KeycloakOauth2Client/Attribute:realm' => 'Realm',
]);
