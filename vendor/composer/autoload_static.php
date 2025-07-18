<?php

// autoload_static.php @generated by Composer

namespace Composer\Autoload;

class ComposerStaticInit59806bb5fc710911a83fe4fe83d82535
{
    public static $prefixLengthsPsr4 = array (
        'H' => 
        array (
            'Hybridauth\\' => 11,
        ),
        'C' => 
        array (
            'Combodo\\iTop\\Oauth2Client\\' => 26,
        ),
    );

    public static $prefixDirsPsr4 = array (
        'Hybridauth\\' => 
        array (
            0 => __DIR__ . '/../..' . '/srcHybridauth',
            1 => __DIR__ . '/..' . '/hybridauth/hybridauth/src',
        ),
        'Combodo\\iTop\\Oauth2Client\\' => 
        array (
            0 => __DIR__ . '/../..' . '/src',
        ),
    );

    public static $classMap = array (
        'Combodo\\iTop\\Oauth2Client\\Controller\\Oauth2ClientController' => __DIR__ . '/../..' . '/src/Controller/Oauth2ClientController.php',
        'Combodo\\iTop\\Oauth2Client\\Helper\\Oauth2ClientException' => __DIR__ . '/../..' . '/src/Helper/Oauth2ClientException.php',
        'Combodo\\iTop\\Oauth2Client\\Helper\\Oauth2ClientHelper' => __DIR__ . '/../..' . '/src/Helper/Oauth2ClientHelper.php',
        'Combodo\\iTop\\Oauth2Client\\Helper\\Oauth2ClientLog' => __DIR__ . '/../..' . '/src/Helper/Oauth2ClientLog.php',
        'Combodo\\iTop\\Oauth2Client\\Hook\\ApplicationUIExtension' => __DIR__ . '/../..' . '/src/Hook/ApplicationUIExtension.php',
        'Combodo\\iTop\\Oauth2Client\\HybridAuth\\AdapterFactoryService' => __DIR__ . '/../..' . '/src/HybridAuth/AdapterFactoryService.php',
        'Combodo\\iTop\\Oauth2Client\\HybridAuth\\AdapterService' => __DIR__ . '/../..' . '/src/HybridAuth/AdapterService.php',
        'Combodo\\iTop\\Oauth2Client\\Model\\Oauth2ClientService' => __DIR__ . '/../..' . '/src/Model/Oauth2ClientService.php',
        'Combodo\\iTop\\Oauth2Client\\Service\\Oauth2Service' => __DIR__ . '/../..' . '/src/Service/Oauth2Service.php',
        'Composer\\InstalledVersions' => __DIR__ . '/..' . '/composer/InstalledVersions.php',
        'Hybridauth\\Adapter\\AbstractAdapter' => __DIR__ . '/..' . '/hybridauth/hybridauth/src/Adapter/AbstractAdapter.php',
        'Hybridauth\\Adapter\\AdapterInterface' => __DIR__ . '/..' . '/hybridauth/hybridauth/src/Adapter/AdapterInterface.php',
        'Hybridauth\\Adapter\\DataStoreTrait' => __DIR__ . '/..' . '/hybridauth/hybridauth/src/Adapter/DataStoreTrait.php',
        'Hybridauth\\Adapter\\FilterService' => __DIR__ . '/..' . '/hybridauth/hybridauth/src/Adapter/FilterService.php',
        'Hybridauth\\Adapter\\OAuth1' => __DIR__ . '/..' . '/hybridauth/hybridauth/src/Adapter/OAuth1.php',
        'Hybridauth\\Adapter\\OAuth2' => __DIR__ . '/..' . '/hybridauth/hybridauth/src/Adapter/OAuth2.php',
        'Hybridauth\\Adapter\\OpenID' => __DIR__ . '/..' . '/hybridauth/hybridauth/src/Adapter/OpenID.php',
        'Hybridauth\\Data\\Collection' => __DIR__ . '/..' . '/hybridauth/hybridauth/src/Data/Collection.php',
        'Hybridauth\\Data\\Parser' => __DIR__ . '/..' . '/hybridauth/hybridauth/src/Data/Parser.php',
        'Hybridauth\\Exception\\AuthorizationDeniedException' => __DIR__ . '/..' . '/hybridauth/hybridauth/src/Exception/AuthorizationDeniedException.php',
        'Hybridauth\\Exception\\BadMethodCallException' => __DIR__ . '/..' . '/hybridauth/hybridauth/src/Exception/BadMethodCallException.php',
        'Hybridauth\\Exception\\Exception' => __DIR__ . '/..' . '/hybridauth/hybridauth/src/Exception/Exception.php',
        'Hybridauth\\Exception\\ExceptionInterface' => __DIR__ . '/..' . '/hybridauth/hybridauth/src/Exception/ExceptionInterface.php',
        'Hybridauth\\Exception\\HttpClientFailureException' => __DIR__ . '/..' . '/hybridauth/hybridauth/src/Exception/HttpClientFailureException.php',
        'Hybridauth\\Exception\\HttpRequestFailedException' => __DIR__ . '/..' . '/hybridauth/hybridauth/src/Exception/HttpRequestFailedException.php',
        'Hybridauth\\Exception\\InvalidAccessTokenException' => __DIR__ . '/..' . '/hybridauth/hybridauth/src/Exception/InvalidAccessTokenException.php',
        'Hybridauth\\Exception\\InvalidApplicationCredentialsException' => __DIR__ . '/..' . '/hybridauth/hybridauth/src/Exception/InvalidApplicationCredentialsException.php',
        'Hybridauth\\Exception\\InvalidArgumentException' => __DIR__ . '/..' . '/hybridauth/hybridauth/src/Exception/InvalidArgumentException.php',
        'Hybridauth\\Exception\\InvalidAuthorizationCodeException' => __DIR__ . '/..' . '/hybridauth/hybridauth/src/Exception/InvalidAuthorizationCodeException.php',
        'Hybridauth\\Exception\\InvalidAuthorizationStateException' => __DIR__ . '/..' . '/hybridauth/hybridauth/src/Exception/InvalidAuthorizationStateException.php',
        'Hybridauth\\Exception\\InvalidOauthTokenException' => __DIR__ . '/..' . '/hybridauth/hybridauth/src/Exception/InvalidOauthTokenException.php',
        'Hybridauth\\Exception\\InvalidOpenidIdentifierException' => __DIR__ . '/..' . '/hybridauth/hybridauth/src/Exception/InvalidOpenidIdentifierException.php',
        'Hybridauth\\Exception\\NotImplementedException' => __DIR__ . '/..' . '/hybridauth/hybridauth/src/Exception/NotImplementedException.php',
        'Hybridauth\\Exception\\RuntimeException' => __DIR__ . '/..' . '/hybridauth/hybridauth/src/Exception/RuntimeException.php',
        'Hybridauth\\Exception\\UnexpectedApiResponseException' => __DIR__ . '/..' . '/hybridauth/hybridauth/src/Exception/UnexpectedApiResponseException.php',
        'Hybridauth\\Exception\\UnexpectedValueException' => __DIR__ . '/..' . '/hybridauth/hybridauth/src/Exception/UnexpectedValueException.php',
        'Hybridauth\\HttpClient\\Curl' => __DIR__ . '/..' . '/hybridauth/hybridauth/src/HttpClient/Curl.php',
        'Hybridauth\\HttpClient\\Guzzle' => __DIR__ . '/..' . '/hybridauth/hybridauth/src/HttpClient/Guzzle.php',
        'Hybridauth\\HttpClient\\HttpClientInterface' => __DIR__ . '/..' . '/hybridauth/hybridauth/src/HttpClient/HttpClientInterface.php',
        'Hybridauth\\HttpClient\\Util' => __DIR__ . '/..' . '/hybridauth/hybridauth/src/HttpClient/Util.php',
        'Hybridauth\\Hybridauth' => __DIR__ . '/..' . '/hybridauth/hybridauth/src/Hybridauth.php',
        'Hybridauth\\Logger\\Logger' => __DIR__ . '/..' . '/hybridauth/hybridauth/src/Logger/Logger.php',
        'Hybridauth\\Logger\\LoggerInterface' => __DIR__ . '/..' . '/hybridauth/hybridauth/src/Logger/LoggerInterface.php',
        'Hybridauth\\Logger\\Psr3LoggerWrapper' => __DIR__ . '/..' . '/hybridauth/hybridauth/src/Logger/Psr3LoggerWrapper.php',
        'Hybridauth\\Provider\\AOLOpenID' => __DIR__ . '/..' . '/hybridauth/hybridauth/src/Provider/AOLOpenID.php',
        'Hybridauth\\Provider\\Amazon' => __DIR__ . '/..' . '/hybridauth/hybridauth/src/Provider/Amazon.php',
        'Hybridauth\\Provider\\Apple' => __DIR__ . '/..' . '/hybridauth/hybridauth/src/Provider/Apple.php',
        'Hybridauth\\Provider\\Authentiq' => __DIR__ . '/..' . '/hybridauth/hybridauth/src/Provider/Authentiq.php',
        'Hybridauth\\Provider\\AutoDesk' => __DIR__ . '/..' . '/hybridauth/hybridauth/src/Provider/AutoDesk.php',
        'Hybridauth\\Provider\\BitBucket' => __DIR__ . '/..' . '/hybridauth/hybridauth/src/Provider/BitBucket.php',
        'Hybridauth\\Provider\\Blizzard' => __DIR__ . '/..' . '/hybridauth/hybridauth/src/Provider/Blizzard.php',
        'Hybridauth\\Provider\\BlizzardAPAC' => __DIR__ . '/..' . '/hybridauth/hybridauth/src/Provider/BlizzardAPAC.php',
        'Hybridauth\\Provider\\BlizzardEU' => __DIR__ . '/..' . '/hybridauth/hybridauth/src/Provider/BlizzardEU.php',
        'Hybridauth\\Provider\\DeviantArt' => __DIR__ . '/..' . '/hybridauth/hybridauth/src/Provider/DeviantArt.php',
        'Hybridauth\\Provider\\Discord' => __DIR__ . '/..' . '/hybridauth/hybridauth/src/Provider/Discord.php',
        'Hybridauth\\Provider\\Disqus' => __DIR__ . '/..' . '/hybridauth/hybridauth/src/Provider/Disqus.php',
        'Hybridauth\\Provider\\Dribbble' => __DIR__ . '/..' . '/hybridauth/hybridauth/src/Provider/Dribbble.php',
        'Hybridauth\\Provider\\Dropbox' => __DIR__ . '/..' . '/hybridauth/hybridauth/src/Provider/Dropbox.php',
        'Hybridauth\\Provider\\Facebook' => __DIR__ . '/..' . '/hybridauth/hybridauth/src/Provider/Facebook.php',
        'Hybridauth\\Provider\\Foursquare' => __DIR__ . '/..' . '/hybridauth/hybridauth/src/Provider/Foursquare.php',
        'Hybridauth\\Provider\\GitHub' => __DIR__ . '/..' . '/hybridauth/hybridauth/src/Provider/GitHub.php',
        'Hybridauth\\Provider\\GitLab' => __DIR__ . '/..' . '/hybridauth/hybridauth/src/Provider/GitLab.php',
        'Hybridauth\\Provider\\Google' => __DIR__ . '/..' . '/hybridauth/hybridauth/src/Provider/Google.php',
        'Hybridauth\\Provider\\Headless' => __DIR__ . '/../..' . '/srcHybridauth/Provider/Headless.php',
        'Hybridauth\\Provider\\Instagram' => __DIR__ . '/..' . '/hybridauth/hybridauth/src/Provider/Instagram.php',
        'Hybridauth\\Provider\\Keycloak' => __DIR__ . '/..' . '/hybridauth/hybridauth/src/Provider/Keycloak.php',
        'Hybridauth\\Provider\\LinkedIn' => __DIR__ . '/..' . '/hybridauth/hybridauth/src/Provider/LinkedIn.php',
        'Hybridauth\\Provider\\LinkedInOpenID' => __DIR__ . '/..' . '/hybridauth/hybridauth/src/Provider/LinkedInOpenID.php',
        'Hybridauth\\Provider\\Mastodon' => __DIR__ . '/..' . '/hybridauth/hybridauth/src/Provider/Mastodon.php',
        'Hybridauth\\Provider\\Medium' => __DIR__ . '/..' . '/hybridauth/hybridauth/src/Provider/Medium.php',
        'Hybridauth\\Provider\\MicrosoftGraph' => __DIR__ . '/..' . '/hybridauth/hybridauth/src/Provider/MicrosoftGraph.php',
        'Hybridauth\\Provider\\ORCID' => __DIR__ . '/..' . '/hybridauth/hybridauth/src/Provider/ORCID.php',
        'Hybridauth\\Provider\\OktaOIDC' => __DIR__ . '/..' . '/hybridauth/hybridauth/src/Provider/OktaOIDC.php',
        'Hybridauth\\Provider\\OpenID' => __DIR__ . '/..' . '/hybridauth/hybridauth/src/Provider/OpenID.php',
        'Hybridauth\\Provider\\Patreon' => __DIR__ . '/..' . '/hybridauth/hybridauth/src/Provider/Patreon.php',
        'Hybridauth\\Provider\\Paypal' => __DIR__ . '/..' . '/hybridauth/hybridauth/src/Provider/Paypal.php',
        'Hybridauth\\Provider\\PaypalOpenID' => __DIR__ . '/..' . '/hybridauth/hybridauth/src/Provider/PaypalOpenID.php',
        'Hybridauth\\Provider\\Pinterest' => __DIR__ . '/..' . '/hybridauth/hybridauth/src/Provider/Pinterest.php',
        'Hybridauth\\Provider\\QQ' => __DIR__ . '/..' . '/hybridauth/hybridauth/src/Provider/QQ.php',
        'Hybridauth\\Provider\\Reddit' => __DIR__ . '/..' . '/hybridauth/hybridauth/src/Provider/Reddit.php',
        'Hybridauth\\Provider\\Seznam' => __DIR__ . '/..' . '/hybridauth/hybridauth/src/Provider/Seznam.php',
        'Hybridauth\\Provider\\Slack' => __DIR__ . '/..' . '/hybridauth/hybridauth/src/Provider/Slack.php',
        'Hybridauth\\Provider\\Spotify' => __DIR__ . '/..' . '/hybridauth/hybridauth/src/Provider/Spotify.php',
        'Hybridauth\\Provider\\StackExchange' => __DIR__ . '/..' . '/hybridauth/hybridauth/src/Provider/StackExchange.php',
        'Hybridauth\\Provider\\StackExchangeOpenID' => __DIR__ . '/..' . '/hybridauth/hybridauth/src/Provider/StackExchangeOpenID.php',
        'Hybridauth\\Provider\\Steam' => __DIR__ . '/..' . '/hybridauth/hybridauth/src/Provider/Steam.php',
        'Hybridauth\\Provider\\SteemConnect' => __DIR__ . '/..' . '/hybridauth/hybridauth/src/Provider/SteemConnect.php',
        'Hybridauth\\Provider\\Strava' => __DIR__ . '/..' . '/hybridauth/hybridauth/src/Provider/Strava.php',
        'Hybridauth\\Provider\\Telegram' => __DIR__ . '/..' . '/hybridauth/hybridauth/src/Provider/Telegram.php',
        'Hybridauth\\Provider\\Tumblr' => __DIR__ . '/..' . '/hybridauth/hybridauth/src/Provider/Tumblr.php',
        'Hybridauth\\Provider\\TwitchTV' => __DIR__ . '/..' . '/hybridauth/hybridauth/src/Provider/TwitchTV.php',
        'Hybridauth\\Provider\\Twitter' => __DIR__ . '/..' . '/hybridauth/hybridauth/src/Provider/Twitter.php',
        'Hybridauth\\Provider\\WeChat' => __DIR__ . '/..' . '/hybridauth/hybridauth/src/Provider/WeChat.php',
        'Hybridauth\\Provider\\WeChatChina' => __DIR__ . '/..' . '/hybridauth/hybridauth/src/Provider/WeChatChina.php',
        'Hybridauth\\Provider\\WindowsLive' => __DIR__ . '/..' . '/hybridauth/hybridauth/src/Provider/WindowsLive.php',
        'Hybridauth\\Provider\\WordPress' => __DIR__ . '/..' . '/hybridauth/hybridauth/src/Provider/WordPress.php',
        'Hybridauth\\Provider\\Yahoo' => __DIR__ . '/..' . '/hybridauth/hybridauth/src/Provider/Yahoo.php',
        'Hybridauth\\Storage\\Session' => __DIR__ . '/..' . '/hybridauth/hybridauth/src/Storage/Session.php',
        'Hybridauth\\Storage\\StorageImpl' => __DIR__ . '/..' . '/hybridauth/hybridauth/src/Storage/StorageImpl.php',
        'Hybridauth\\Storage\\StorageInterface' => __DIR__ . '/..' . '/hybridauth/hybridauth/src/Storage/StorageInterface.php',
        'Hybridauth\\Thirdparty\\OAuth\\OAuthConsumer' => __DIR__ . '/..' . '/hybridauth/hybridauth/src/Thirdparty/OAuth/OAuthConsumer.php',
        'Hybridauth\\Thirdparty\\OAuth\\OAuthRequest' => __DIR__ . '/..' . '/hybridauth/hybridauth/src/Thirdparty/OAuth/OAuthRequest.php',
        'Hybridauth\\Thirdparty\\OAuth\\OAuthSignatureMethod' => __DIR__ . '/..' . '/hybridauth/hybridauth/src/Thirdparty/OAuth/OAuthSignatureMethod.php',
        'Hybridauth\\Thirdparty\\OAuth\\OAuthSignatureMethodHMACSHA1' => __DIR__ . '/..' . '/hybridauth/hybridauth/src/Thirdparty/OAuth/OAuthSignatureMethodHMACSHA1.php',
        'Hybridauth\\Thirdparty\\OAuth\\OAuthUtil' => __DIR__ . '/..' . '/hybridauth/hybridauth/src/Thirdparty/OAuth/OAuthUtil.php',
        'Hybridauth\\Thirdparty\\OpenID\\LightOpenID' => __DIR__ . '/..' . '/hybridauth/hybridauth/src/Thirdparty/OpenID/LightOpenID.php',
        'Hybridauth\\User\\Activity' => __DIR__ . '/..' . '/hybridauth/hybridauth/src/User/Activity.php',
        'Hybridauth\\User\\Contact' => __DIR__ . '/..' . '/hybridauth/hybridauth/src/User/Contact.php',
        'Hybridauth\\User\\Profile' => __DIR__ . '/..' . '/hybridauth/hybridauth/src/User/Profile.php',
    );

    public static function getInitializer(ClassLoader $loader)
    {
        return \Closure::bind(function () use ($loader) {
            $loader->prefixLengthsPsr4 = ComposerStaticInit59806bb5fc710911a83fe4fe83d82535::$prefixLengthsPsr4;
            $loader->prefixDirsPsr4 = ComposerStaticInit59806bb5fc710911a83fe4fe83d82535::$prefixDirsPsr4;
            $loader->classMap = ComposerStaticInit59806bb5fc710911a83fe4fe83d82535::$classMap;

        }, null, ClassLoader::class);
    }
}
