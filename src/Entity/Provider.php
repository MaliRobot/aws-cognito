<?php
namespace malirobot\AwsCognito\Entity;

final class Provider {

    private string $appClientId;
    private string $appRegion;
    private string $appName;
    private string $appRedirectUri;

    public function __construct(string $appClientId,string $appRegion, string $appName, string $appRedirectUri)
    {
        $this->appClientId = $appClientId;
        $this->appRegion = $appRegion;
        $this->appName = $appName;
        $this->appRedirectUri = $appRedirectUri;
    }
    /**
     * Retrieves the parameters for a given provider.
     *
     * @param string $provider_name The name of the provider.
     * @return array The parameters for the provider.
     */
    private function params(string $provider_name): array
    {
        return [
            'client_id' => $this->appClientId,
            'redirect_uri' => $this->appRedirectUri,
            'response_type' => 'code',
            'scope' => 'email profile openid aws.cognito.signin.user.admin',
            'identity_provider' => $provider_name,
            'state' => uniqid($this->appName, true),
        ];
    }

    /**
     * Returns the Google provider.
     * @param string $authUrl The URL to authenticate.
     * @return string The Google provider.
     */
    public function google(string $authUrl) : string
    {
        return $authUrl . '?' . http_build_query(self::params('google'));
    }

    /**
     * Retrieves the parameters for a specific provider.
     *
     * @param string $provider_name The name of the provider.
     * @return array The parameters for the provider.
     */
    public function getParams(string $provider_name): array
    {
        return self::params($provider_name);
    }



    /**
     * Generates the URL for a specific provider.
     *
     * @param string $providerName The name of the provider.
     * @return string The URL for the provider.
     */
    public static function providerUrl(string $providerName): string 
    {
        switch($providerName) {
            case 'google':
                return 'https://accounts.google.com/o/oauth2/auth';
            case 'facebook':
                return 'https://www.facebook.com/v3.3/dialog/oauth';
            case 'linkedin':
                return 'https://www.linkedin.com/oauth/v2/authorization';
            default:
                throw new \Exception('Provider not found');
        }
    }
    
}