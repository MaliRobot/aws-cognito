<?php
namespace malirobot\AwsCognito\Entity;

final class Provider {

    private string $appClientId;
    private string $appRegion;
    private string $appName;

    public function __construct(string $appClientId,string $appRegion, string $appName)
    {
        $this->appClientId = $appClientId;
        $this->appRegion = $appRegion;
        $this->appName = $appName;
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
            'redirect_uri' => "https://".$this->appName.".auth.".$this->appRegion.".amazoncognito.com/oauth2/authorize",
            'response_type' => 'code',
            'scope' => 'email profile openid aws.cognito.signin.user.admin',
            'identity_provider' => $provider_name,
            'state' => uniqid($this->appName, true),
        ];
    }

    /**
     * Authenticates the user using Google as the identity provider.
     *
     * @param string $redirect_uri The URI to redirect the user after authentication.
     * @return string The authentication URL for Google.
     */
    public function google(string $redirect_uri) : string
    {
        $authUrl = $redirect_uri;
        return $authUrl . '?' . http_build_query(self::params('google'));
    }

    /**
     * Authenticates the user using Facebook.
     *
     * @param string $redirect_uri The URI to redirect the user after authentication.
     * @return string The authentication result.
     */
    public function facebook(string $redirect_uri) : string
    {
        $authUrl = $redirect_uri;
        return $authUrl . '?' . http_build_query(self::params('facebook'));
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
    
}