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
    private function params(string $provider_name, array $scopes = ['openid']): array
    {
        $scopes = implode(' ', $scopes);

        return [
            'client_id' => $this->appClientId,
            'redirect_uri' => $this->appRedirectUri,
            'response_type' => 'code',
            'scope' => $scopes,
            'identity_provider' => $provider_name,
            'state' => uniqid($this->appName, true),
        ];
    }

    /**
     * Returns the Google provider.
     * @return string The Google provider.
     */
    public function google() : string
    {
        return $this->authUrl() . '?' . http_build_query(self::params('google'));
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
     * Returns the authentication URL for the provider.
     *
     * @return string The authentication URL.
     */
    private function authUrl()
    {
        return 'https://'.$this->appName.'.auth.'.$this->appRegion.'.amazoncognito.com/oauth2/authorize';
    }
    
}