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
]);
