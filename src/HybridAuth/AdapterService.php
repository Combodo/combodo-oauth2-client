<?php

namespace Combodo\iTop\Oauth2Client\HybridAuth;

use Combodo\iTop\Oauth2Client\Helper\Oauth2ClientException;
use Combodo\iTop\Oauth2Client\Helper\Oauth2ClientHelper;
use Combodo\iTop\Oauth2Client\Helper\Oauth2ClientLog;
use Dict;
use Exception;
use Hybridauth\Adapter\AdapterInterface;
use Hybridauth\HttpClient\HttpClientInterface;
use Hybridauth\Storage\StorageInterface;
use ReflectionClass;
use utils;

class AdapterService
{
	private static AdapterService $oInstance;
	private string $sName;
	private string $sProvider;
	private string $sProviderName;
	private AdapterInterface $oAuth2;
	private ?HttpClientInterface $oHttpClient;
	private ?StorageInterface $oStorage;

	protected function __construct()
	{
		Oauth2ClientLog::Enable();
	}

	final public static function GetInstance(): AdapterService
	{
		if (!isset(static::$oInstance)) {
			static::$oInstance = new static();
		}

		return static::$oInstance;
	}

	final public static function SetInstance(?AdapterService $oInstance): void
	{
		static::$oInstance = $oInstance;
	}

	/**
	 * @param string $sName
	 * @param string $sProvider provider class fqdn
	 * @param ?HttpClientInterface $oHttpClient
	 * @param ?StorageInterface $storage
	 *
	 * @return void
	 */
	public function Init(string $sName, string $sProvider, ?HttpClientInterface $oHttpClient=null, ?StorageInterface $oStorage=null): void
	{
		Oauth2ClientLog::Debug(__FUNCTION__, null, [$sName, $sProvider]);
		$this->sName = $sName;
		$this->sProvider = $sProvider;
		$this->sProviderName = Oauth2ClientHelper::GetProviderName($sProvider);
		$this->oHttpClient = $oHttpClient;
		$this->oStorage = $oStorage;
	}

	/**
	 * @param array $aConfig
	 *
	 * @return void
	 * @throws \Combodo\iTop\Oauth2Client\Helper\Oauth2ClientException
	 */
	public function InitOauth2(array $aConfig): void
	{
		try {
			$this->oAuth2 = AdapterFactoryService::GetInstance()->GetAdapterInterface($this->sProviderName, $aConfig,
				null, $this->oHttpClient, $this->oStorage);
			$sAuthorizationState = $aConfig['authorization_state'] ?? null;
			if (utils::IsNotNullOrEmptyString($sAuthorizationState)) {
				$this->storeData('authorization_state', $sAuthorizationState);
			}
		} catch (Exception $e) {
			throw new Oauth2ClientException(__FUNCTION__.': failed', 0, $e);
		}
	}

	/**
	 * @param array $aConfig
	 *
	 * @return void
	 * @throws \Combodo\iTop\Oauth2Client\Helper\Oauth2ClientException
	 */
	public function Authenticate(array $aConfig): void
	{
		Oauth2ClientLog::Debug(__FUNCTION__, null, $aConfig);
		$this->InitOauth2($aConfig);

		$this->oAuth2->disconnect();
		$this->oAuth2->authenticate();
	}

	/**
	 * @param array $aConfig
	 *
	 * @return array
	 * @throws \Combodo\iTop\Oauth2Client\Helper\Oauth2ClientException
	 */
	public function AuthenticateFinish(array $aConfig): array
	{
		try {
			Oauth2ClientLog::Debug(__FUNCTION__, null, $aConfig);
			$this->InitOauth2($aConfig);
			$this->oAuth2->authenticate();
			$aTokens = $this->oAuth2->getAccessToken();
			$aTokens['authorization_state'] = $this->GetAuthorizationState();
			Oauth2ClientLog::Debug(__FUNCTION__, null, $aTokens);

			return $aTokens;
		} catch (Oauth2ClientException $e) {
			throw $e;
		} catch (Exception $e) {
			throw new Oauth2ClientException(__FUNCTION__.': failed', 0, $e);
		}
	}

	/**
	 * @param array $aConfig
	 *
	 * @return array
	 * @throws \Combodo\iTop\Oauth2Client\Helper\Oauth2ClientException
	 */
	public function RefreshToken(array $aConfig): array
	{
		try {
			Oauth2ClientLog::Debug(__FUNCTION__, null, $aConfig);
			$this->InitOauth2($aConfig);// refresh tokens if needed
			$this->oAuth2->maintainToken();
			$hasAccessTokenExpired = $this->oAuth2->hasAccessTokenExpired();
			Oauth2ClientLog::Debug(__FUNCTION__, null, ['hasAccessTokenExpired' => $hasAccessTokenExpired]);
			if ($hasAccessTokenExpired === true) {
				Oauth2ClientLog::Debug(__FUNCTION__, null, ['isRefreshTokenAvailable' => $this->oAuth2->isRefreshTokenAvailable()]);
				$sResponse = $this->oAuth2->refreshAccessToken();
				if (is_null($sResponse)) {
					throw new Oauth2ClientException(Dict::S('Oauth2Client:UI:Error:RefreshTokenNotAvailable'));
				}

				Oauth2ClientLog::Debug(__FUNCTION__, null, ['refresh token response' => $sResponse]);
			}
			$aTokens = $this->oAuth2->getAccessToken();
			$aTokens['authorization_state'] = $this->GetAuthorizationState();
			Oauth2ClientLog::Debug(__FUNCTION__, null, $aTokens);

			return $aTokens;
		} catch (Oauth2ClientException $e) {
			throw $e;
		} catch (Exception $e) {
			throw new Oauth2ClientException(__FUNCTION__.': failed', 0, $e);
		}
	}

	/**
	 * @return string
	 * @throws \Combodo\iTop\Oauth2Client\Helper\Oauth2ClientException
	 */
	private function GetAuthorizationState(): string
	{
		try {
			$sRequestMethod = $_SERVER['REQUEST_METHOD'] ?? 'GET';
			if ($sRequestMethod === 'POST') {
				$sAuthorizationState = utils::ReadPostedParam('state', '', utils::ENUM_SANITIZATION_FILTER_STRING);
			} else {
				$sAuthorizationState = utils::ReadParam('state', '', false, utils::ENUM_SANITIZATION_FILTER_STRING);
			}
			Oauth2ClientLog::Debug(__FUNCTION__, null, [$sAuthorizationState]);

			return $sAuthorizationState;
		} catch (Exception $e) {
			throw new Oauth2ClientException(__FUNCTION__.': failed', 0, $e);
		}
	}

	/**
	 * @return string
	 * @throws \Combodo\iTop\Oauth2Client\Helper\Oauth2ClientException
	 */
	public function GetDefaultScope(): string
	{
		try {
			/** @noinspection OneTimeUseVariablesInspection */
			$oClass = new ReflectionClass($this->oAuth2);
			$oProperty = $oClass->getProperty('scope');
			$oProperty->setAccessible(true);

			return $oProperty->getValue($this->oAuth2);
		} catch (Exception $e) {
			throw new Oauth2ClientException(__FUNCTION__.': failed', 0, $e);
		}
	}

	/**
	 * @param string $name
	 * @param mixed $value
	 *
	 * @return mixed
	 * @throws \Combodo\iTop\Oauth2Client\Helper\Oauth2ClientException
	 */
	public function storeData(string $name, $value = null) : void
	{
		try {
			/** @noinspection OneTimeUseVariablesInspection */
			$oClass = new ReflectionClass($this->oAuth2);
			$method = $oClass->getMethod('storeData');
			$method->setAccessible(true);

			$method->invokeArgs($this->oAuth2, [$name, $value]);
		} catch (\Exception $e) {
			throw new Oauth2ClientException(__FUNCTION__.': failed', 0, $e);
		}
	}

	public function ListProviders() : array {
		$aList = [];

		$sPath = __DIR__ . '/../../vendor/hybridauth/hybridauth/src/Provider/';
		$oFilesystemIterator = new \FilesystemIterator($sPath);
		/** @var \SplFileInfo $file */
		foreach ($oFilesystemIterator as $file) {
			if (!$file->isDir()) {
				$sProvider = strtok($file->getFilename(), '.');
				$sClass = sprintf('Hybridauth\\Provider\\%s', $sProvider);
				$oReflectionClass = new \ReflectionClass($sClass);
				if ($oReflectionClass->implementsInterface(AdapterInterface::class)) {
					$aList [] = $sProvider;
				}
			}
		}
		return $aList;
	}
}
