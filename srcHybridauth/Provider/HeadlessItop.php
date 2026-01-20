<?php
/*!
* Hybridauth
* https://hybridauth.github.io | https://github.com/hybridauth/hybridauth
*  (c) 2020 Hybridauth authors | https://hybridauth.github.io/license.html
*/

namespace Hybridauth\Provider;

use Hybridauth\Adapter\OAuth2;
use Hybridauth\Exception\Exception;
use Hybridauth\Exception\InvalidApplicationCredentialsException;

/**
 * Itop OAuth2 Identity Provider adapter.
 * This provider is not interactive, the User's credentials are given during the connection along with application credentials
 */
class HeadlessItop extends Headless
{
	/**
	 * {@inheritdoc}
	 */
	protected $scope = 'account_info.read';

	/**
	 * {@inheritdoc}
	 */
	protected $apiDocumentation = 'https://www.itophub.io/wiki/page?id=start';

	/**
	 * {@inheritdoc}
	 */
	protected function configure()
	{
		parent::configure();

		$this->authorizeUrl = $this->apiBaseUrl.'/pages/exec.php?exec_module=authent-oauth&exec_page=auth.php';
		$this->accessTokenUrl = $this->authorizeUrl;
	}
}
