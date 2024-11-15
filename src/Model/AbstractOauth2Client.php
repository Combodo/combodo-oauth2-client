<?php

namespace Combodo\iTop\Oauth2Client\Model;

use cmdbAbstractObject;
use Hybridauth\Adapter\OAuth2;

abstract class AbstractOauth2Client extends cmdbAbstractObject {
	private Oauth2 $oAuth2;

	/**
	 * @return \Hybridauth\Adapter\OAuth2
	 */
	public function GetOauth2(): Oauth2 {
		return $this->oAuth2;
	}

	/**
	 * @param \Hybridauth\Adapter\OAuth2 $oAuth2
	 *
	 * @return void
	 */
	public function SetOauth2(OAuth2 $oAuth2): void {
		$this->oAuth2 = $oAuth2;
	}


}
