<?php

namespace malirobot\AwsCognito;

use Exception;
use GuzzleHttp\Client;
use Jose\Component\Core\JWKSet;
use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Signature\JWSVerifier;
use Jose\Component\KeyManagement\JWKFactory;
use Jose\Component\Signature\Algorithm\RS256;
use malirobot\AwsCognito\Exception\ChallengeException;
use malirobot\AwsCognito\Exception\TokenExpiryException;
use Jose\Component\Signature\Serializer\CompactSerializer;
use malirobot\AwsCognito\Exception\CognitoResponseException;
use Aws\CognitoIdentityProvider\CognitoIdentityProviderClient;
use malirobot\AwsCognito\Exception\TokenVerificationException;
use Aws\CognitoIdentityProvider\Exception\CognitoIdentityProviderException;
use malirobot\AwsCognito\Entity\Provider;

class CognitoClient
{
    const CHALLENGE_NEW_PASSWORD_REQUIRED = 'NEW_PASSWORD_REQUIRED';

    /**
     * @var string
     */
    protected $appClientId;

    /**
     * @var string
     */
    protected $appClientSecret;

    /**
     * @var CognitoIdentityProviderClient
     */
    protected $client;

    /**
     * @var JWKSet
     */
    protected $jwtWebKeys;

    /**
     * @var string
     */
    protected $region;

    /**
     * @var string
     */
    protected $userPoolId;

    /**
     * @var bool
     */
    protected $boolClientSecret = false;

    /**
     *  @var string
     */
    protected $appName;

    /**
     * CognitoClient constructor.
     *
     * @param CognitoIdentityProviderClient $client
     */
    public function __construct(CognitoIdentityProviderClient $client)
    {
        $this->client = $client;
    }

    /**
     * @param string $username
     * @param string $password
     *
     * @return array
     * @throws ChallengeException
     * @throws Exception
     */
    public function authenticate($username, $password)
    {
        try {
            $payload = [
                'AuthFlow' => 'ADMIN_NO_SRP_AUTH',
                'AuthParameters' => [
                    'USERNAME' => $username,
                    'PASSWORD' => $password
                ],
                'ClientId' => $this->appClientId,
                'UserPoolId' => $this->userPoolId,
            ];

            //Add Secret Hash in case of Client Secret being configured
            if ($this->boolClientSecret) {
                $payload['AuthParameters'] = array_merge($payload['AuthParameters'], [
                    'SECRET_HASH' => $this->cognitoSecretHash($username)
                ]);
            } //End if

            $response = $this->client->adminInitiateAuth($payload);
            return $this->handleAuthenticateResponse($response->toArray());
        } catch (\Exception $e) {
            return ["error" => $e->getMessage()];
        }
    }

    /**
     * @param string $challengeName
     * @param array $challengeResponses
     * @param string $session
     *
     * @return array
     * @throws ChallengeException
     * @throws Exception
     */
    public function respondToAuthChallenge($challengeName, array $challengeResponses, $session)
    {
        try {
            $response = $this->client->respondToAuthChallenge([
                'ChallengeName' => $challengeName,
                'ChallengeResponses' => $challengeResponses,
                'ClientId' => $this->appClientId,
                'Session' => $session,
            ]);

            return $this->handleAuthenticateResponse($response->toArray());
        } catch (\Exception $e) {
            return ["error" => $e->getMessage()];
        }
    }

    /**
     * @param string $username
     * @param string $newPassword
     * @param string $session
     * @return array
     * @throws ChallengeException
     * @throws Exception
     */
    public function respondToNewPasswordRequiredChallenge($username, $newPassword, $session)
    {
        return $this->respondToAuthChallenge(
            self::CHALLENGE_NEW_PASSWORD_REQUIRED,
            [
                'NEW_PASSWORD' => $newPassword,
                'USERNAME' => $username,
                'SECRET_HASH' => $this->cognitoSecretHash($username),
            ],
            $session
        );
    }

    /**
     * @param string $username
     * @param string $refreshToken
     * @return string
     * @throws Exception
     */
    public function refreshAuthentication($username, $refreshToken)
    {
        try {
            $response = $this->client->adminInitiateAuth([
                'AuthFlow' => 'REFRESH_TOKEN_AUTH',
                'AuthParameters' => [
                    'USERNAME' => $username,
                    'REFRESH_TOKEN' => $refreshToken,
                    'SECRET_HASH' => $this->cognitoSecretHash($username),
                ],
                'ClientId' => $this->appClientId,
                'UserPoolId' => $this->userPoolId,
            ])->toArray();

            return $response['AuthenticationResult'];
        } catch (CognitoIdentityProviderException $e) {
            throw CognitoResponseException::createFromCognitoException($e);
        }
    }

    /**
     * @param string $accessToken
     * @param string $previousPassword
     * @param string $proposedPassword
     * @throws Exception
     * @throws TokenExpiryException
     * @throws TokenVerificationException
     */
    public function changePassword($accessToken, $previousPassword, $proposedPassword, $verifyToken = False)
    {
        if ($verifyToken) {
            $this->verifyAccessToken($accessToken);
        }

        try {
            $this->client->changePassword([
                'AccessToken' => $accessToken,
                'PreviousPassword' => $previousPassword,
                'ProposedPassword' => $proposedPassword,
            ]);
            return ["success" => "password changed"];
        } catch (\Exception $e) {
            return ["error" => $e->getMessage()];
        }
    }

    /**
     * @param string $confirmationCode
     * @param string $username
     * @throws Exception
     */
    public function confirmUserRegistration($confirmationCode, $username)
    {
        try {
            $this->client->confirmSignUp([
                'ClientId' => $this->appClientId,
                'ConfirmationCode' => $confirmationCode,
                'SecretHash' => $this->cognitoSecretHash($username),
                'Username' => $username,
            ]);
        } catch (CognitoIdentityProviderException $e) {
            throw CognitoResponseException::createFromCognitoException($e);
        }
    }

    /**
     * @param $username
     * @param $email
     * @param $tempPassword
     * @param array $attributes
     * @return array
     * @throws Exception
     */
    public function createUser($username, $email, $tempPassword, $attributes = [])
    {
        try {
            $userAttributes = $this->buildAttributesArray($attributes);

            $response = $this->client->adminCreateUser([
                'TemporaryPassword' => $tempPassword,
                'UserAttributes' => $userAttributes,
                'Username' => $username,
                'UserPoolId' => $this->userPoolId,
                'ValidationData' => [
                    [
                        'Name' => 'email',
                        'Value' => $email,
                    ],
                ],
            ]);
            return $response->toArray();
        } catch (\Exception $e) {
            return ['error' => $e->getMessage()];
        }
    }

    /**
     * @param $username
     * @return array
     * @throws Exception
     */
    public function getUser($username)
    {
        try {
            $response = $this->client->adminGetUser([
                'Username' => $username,
                'UserPoolId' => $this->userPoolId,
            ]);
            return $response->toArray();
        } catch (\Exception $e) {
            return ["error" => $e->getMessage()];
        }
    }


    public function getUsers($attributes = [], $filter = null, $limit = null, $paginationToken = null)
    {
        try {
            $paramsArray = ['AttributesToGet' => $attributes, 'UserPoolId' => $this->userPoolId];
            if ($filter) {
                $paramsArray[] = ['Filter' => $filter];
            }
            if ($limit) {
                $paramsArray[] = ['Limit' => $limit];
            }
            if ($paginationToken) {
                $paramsArray[] = ['PaginationToken' => $paginationToken];
            }

            $result = $this->client->listUsers($paramsArray);
            return $result->toArray();
        } catch (\Exception $e) {
            return ["error" => $e->getMessage()];
        }
    }

    /**
     * @param string $accessToken
     * @throws Exception
     * @throws TokenExpiryException
     * @throws TokenVerificationException
     */
    public function deleteUser($accessToken)
    {
        $this->verifyAccessToken($accessToken);

        try {
            $this->client->deleteUser([
                'AccessToken' => $accessToken,
            ]);
        } catch (CognitoIdentityProviderException $e) {
            throw CognitoResponseException::createFromCognitoException($e);
        }
    }

    /**
     * @param $username
     * @throws Exception
     */
    public function deleteUserAsAdmin($username)
    {
        try {
            $this->client->adminDeleteUser([
                'UserPoolId' => $this->userPoolId,
                'Username' => $username
            ]);
            return ["success" => "user deleted"];
        } catch (\Exception $e) {
            return ["error" => $e->getMessage()];
        }
    }

    /**
     * @param $username
     * @throws Exception
     */
    public function enableUser($username)
    {
        try {
            $this->client->adminEnableUser([
                'UserPoolId' => $this->userPoolId,
                'Username' => $username
            ]);
        } catch (CognitoIdentityProviderException $e) {
            throw CognitoResponseException::createFromCognitoException($e);
        }
    }

    /**
     * @param $username
     * @throws Exception
     */
    public function disableUser($username)
    {
        try {
            $this->client->adminDisableUser([
                'UserPoolId' => $this->userPoolId,
                'Username' => $username
            ]);
        } catch (CognitoIdentityProviderException $e) {
            throw CognitoResponseException::createFromCognitoException($e);
        }
    }

    /**
     * @param $description
     * @param $groupName
     * @param $precedence
     * @param $roleArn
     * @throws Exception
     */
    public function createGroup($description, $groupName, $precedence, $roleArn)
    {
        try {
            $requestArray = [
                'Description' => $description,
                'GroupName' => $groupName,
                'UserPoolId' => $this->userPoolId
            ];
            if ($precedence != null) {
                $requestArray['Precedence'] = $precedence;
            }
            if ($roleArn != null) {
                $requestArray['RoleArn'];
            }
            $result = $this->client->createGroup($requestArray);
            return $result->toArray();
        } catch (\Exception $e) {
            return ["error" => $e->getMessage()];
        }
    }

    public function deleteGroup($groupname)
    {
        try {
            $result = $this->client->deleteGroup([
                'GroupName' => $groupname,
                'UserPoolId' => $this->userPoolId
            ]);
            return $result->toArray();
        } catch (\Exception $e) {
            return ["error" => $e->getMessage()];
        }
    }

    /**
     * @param string $username
     * @throws Exception
     */
    public function getGroup($group)
    {
        try {
            $response = $this->client->getGroup([
                'UserPoolId' => $this->userPoolId,
                'GroupName' => $group,
            ]);
            return $response->toArray();
        } catch (\Exception $e) {
            return ["error" => $e->getMessage()];
        }
    }

    /**
     * @param null $limit
     * @param null $nextToken
     * @return array
     */
    public function getGroups($limit = null, $nextToken = null)
    {
        try {
            $paramsArray = [];
            if ($limit) {
                $paramsArray['Limit'] = $limit;
            }
            if ($nextToken) {
                $paramsArray['NextToken'] = $nextToken;
            }
            $paramsArray['UserPoolId'] = $this->userPoolId;
            $response = $this->client->listGroups($paramsArray);
            return $response->toArray();
        } catch (\Exception $e) {
            return ["error" => $e->getMessage()];
        }
    }

    /**
     * @param string $username
     * @throws Exception
     */
    public function getGroupMembers($group)
    {
        try {
            $response = $this->client->listUsersInGroup([
                'UserPoolId' => $this->userPoolId,
                'GroupName' => $group,
            ]);
            return $response->toArray();
        } catch (\Exception $e) {
            return ["error" => $e->getMessage()];
        }
    }

    /**
     * @param string $username
     * @param string $groupName
     * @throws Exception
     */
    public function addUserToGroup($username, $groupName)
    {
        try {
            $this->client->admin([
                'UserPoolId' => $this->userPoolId,
                'Username' => $username,
                "GroupName" => $groupName
            ]);
        } catch (CognitoIdentityProviderException $e) {
            throw CognitoResponseException::createFromCognitoException($e);
        }
    }

    /**
     * @param string $username
     * @param string $groupName
     * @throws Exception
     */
    public function removeUserFromGroup($username, $groupName)
    {
        try {
            $this->client->adminRemoveUserFromGroup([
                'UserPoolId' => $this->userPoolId,
                'Username' => $username,
                "GroupName" => $groupName
            ]);
        } catch (CognitoIdentityProviderException $e) {
            throw CognitoResponseException::createFromCognitoException($e);
        }
    }

    /**
     * @param $username
     * @param array $attributes
     * @throws Exception
     */
    public function updateUserAttributes($username, array $attributes = [])
    {
        $userAttributes = $this->buildAttributesArray($attributes);

        try {
            $this->client->adminUpdateUserAttributes([
                'Username' => $username,
                'UserPoolId' => $this->userPoolId,
                'UserAttributes' => $userAttributes,
            ]);
        } catch (CognitoIdentityProviderException $e) {
            throw CognitoResponseException::createFromCognitoException($e);
        }
    }

    /**
     * @return JWKSet
     */
    public function getJwtWebKeys()
    {
        if (!$this->jwtWebKeys) {
            $json = $this->downloadJwtWebKeys();
            $this->jwtWebKeys = JWKSet::createFromJson($json);
        }

        return $this->jwtWebKeys;
    }

    /**
     * @param JWKSet $jwtWebKeys
     */
    public function setJwtWebKeys(JWKSet $jwtWebKeys)
    {
        $this->jwtWebKeys = $jwtWebKeys;
    }

    /**
     * @return string
     */
    protected function downloadJwtWebKeys()
    {
        $url = sprintf(
            'https://cognito-idp.%s.amazonaws.com/%s/.well-known/jwks.json',
            $this->region,
            $this->userPoolId
        );

        return file_get_contents($url);
    }

    /**
     * @param string $username
     * @param string $password
     * @param array $attributes
     * @return string
     * @throws Exception
     */
    public function registerUser($username, $password, array $attributes = [])
    {
        $userAttributes = $this->buildAttributesArray($attributes);

        try {
            $response = $this->client->signUp([
                'ClientId' => $this->appClientId,
                'Password' => $password,
                'SecretHash' => $this->cognitoSecretHash($username),
                'UserAttributes' => $userAttributes,
                'Username' => $username,
            ]);

            return $response['UserSub'];
        } catch (CognitoIdentityProviderException $e) {
            throw CognitoResponseException::createFromCognitoException($e);
        }
    }

    /**
     * @param string $confirmationCode
     * @param string $username
     * @param string $proposedPassword
     * @throws Exception
     */
    public function resetPassword($confirmationCode, $username, $proposedPassword)
    {
        try {
            $this->client->confirmForgotPassword([
                'ClientId' => $this->appClientId,
                'ConfirmationCode' => $confirmationCode,
                'Password' => $proposedPassword,
                'SecretHash' => $this->cognitoSecretHash($username),
                'Username' => $username,
            ]);
            return ["success" => "reset password request sent"];
        } catch (\Exception $e) {
            return ["error" => $e->getMessage()];
        }
    }

    /**
     * @param string $username
     * @throws Exception
     */
    public function resendRegistrationConfirmationCode($username)
    {
        try {
            $this->client->resendConfirmationCode([
                'ClientId' => $this->appClientId,
                'SecretHash' => $this->cognitoSecretHash($username),
                'Username' => $username,
            ]);
        } catch (CognitoIdentityProviderException $e) {
            throw CognitoResponseException::createFromCognitoException($e);
        }
    }

    /**
     * @param string $username
     * @throws Exception
     */
    public function sendForgottenPasswordRequest($username)
    {
        try {
            $this->client->forgotPassword([
                'ClientId' => $this->appClientId,
                'SecretHash' => $this->cognitoSecretHash($username),
                'Username' => $username,
            ]);
            return ["success" => "password request submitted"];
        } catch (\Exception $e) {
            return $e->getMessage();
        }
    }

    /**
     * @param string $appClientId
     */
    public function setAppClientId($appClientId)
    {
        $this->appClientId = $appClientId;
    }

    /**
     * @param string $appClientSecret
     */
    public function setAppClientSecret($appClientSecret)
    {
        $this->appClientSecret = $appClientSecret;
    }

    /**
     * @param CognitoIdentityProviderClient $client
     */
    public function setClient($client)
    {
        $this->client = $client;
    }

    /**
     * @param string $region
     */
    public function setRegion($region)
    {
        $this->region = $region;
    }

    /**
     * @param string $userPoolId
     */
    public function setUserPoolId($userPoolId)
    {
        $this->userPoolId = $userPoolId;
    }

    /**
     * @param string $accessToken
     * @return array
     * @throws TokenVerificationException
     */
    public function decodeAccessToken($accessToken)
    {
        // Create the secret key
        $secretKey = $this->downloadJwtWebKeys();
        // Create a JWK (JSON Web Key) object from the secret key
        /** @var \Jose\Component\Core\JWKSet $jwk */
        $jwk = JWKFactory::createFromJsonObject(
            $secretKey
        );

        // Initialize the AlgorithmManager
        $algorithmManager = new AlgorithmManager([new RS256()]);

        // Create the JWSVerifier
        $jwsVerifier = new JWSVerifier($algorithmManager);

        // Create the CompactSerializer
        $serializer = new CompactSerializer();

        try {
            // Deserialize the JWT token
            $jws = $serializer->unserialize($accessToken);

            // Validate the JWT token using the public key
            if ($jwsVerifier->verifyWithKeySet($jws, $jwk, 0)) {
            // The JWT token is valid
            // Extract the payload
            $payload = json_decode($jws->getPayload(), true);
            } else {
            // The JWT token is not valid
            $payload = [];
            }
        } catch (\Exception $e) {
            // Error handling
            throw new TokenVerificationException('Invalid token');
        }
        
        return $payload;
    }

    /**
     * Verifies the given access token and returns the username
     *
     * @param string $accessToken
     *
     * @throws TokenExpiryException
     * @throws TokenVerificationException
     *
     * @return string
     */
    public function verifyAccessToken($accessToken)
    {
        $jwtPayload = $this->decodeAccessToken($accessToken);

        $expectedIss = sprintf('https://cognito-idp.%s.amazonaws.com/%s', $this->region, $this->userPoolId);
        if ($jwtPayload['iss'] !== $expectedIss) {
            throw new TokenVerificationException('invalid iss');
        }

        if ($jwtPayload['token_use'] !== 'access') {
            throw new TokenVerificationException('invalid token_use');
        }

        if ($jwtPayload['exp'] < time()) {
            throw new TokenExpiryException('invalid exp');
        }

        return $jwtPayload['username'];
    }

    /**
     * @param string $username
     *
     * @return string
     */
    public function cognitoSecretHash($username)
    {
        return $this->hash($username . $this->appClientId);
    }

    /**
     * @param string $message
     *
     * @return string
     */
    protected function hash($message)
    {
        $hash = hash_hmac(
            'sha256',
            $message,
            $this->appClientSecret,
            true
        );

        return base64_encode($hash);
    }

    /**
     * @param array $response
     * @return array
     * @throws ChallengeException
     * @throws Exception
     */
    protected function handleAuthenticateResponse(array $response)
    {
        if (isset($response['AuthenticationResult'])) {
            return $response['AuthenticationResult'];
        }

        if (isset($response['ChallengeName'])) {
            throw ChallengeException::createFromAuthenticateResponse($response);
        }

        throw new Exception('Could not handle AdminInitiateAuth response');
    }

    /**
     * @param array $attributes
     * @return array
     */
    private function buildAttributesArray(array $attributes): array
    {
        $userAttributes = [];
        foreach ($attributes as $key => $value) {
            $userAttributes[] = [
                'Name' => (string)$key,
                'Value' => (string)$value,
            ];
        }
        return $userAttributes;
    }

    /**
     * Sets the email verification status for a user.
     *
     * @param string $username The username of the user.
     * @return void
     */
    public function setUserEmailVerified($username)
    {
        $attributes = [
            'email_verified' => 'true',
        ];

        $this->updateUserAttributes($username, $attributes);
    }

    /**
     * Sets the password for a user in the Cognito user pool.
     *
     * @param string $username The username of the user.
     * @param string $password The new password for the user.
     * @param bool $permanent (optional) Whether the password change is permanent. Default is false.
     * @return void
     */
    public function setUserPassword($username, $password, $permanent = false)
    {
        $this->client->adminSetUserPassword([
            'Password' => $password,
            'Permanent' => $permanent,
            'Username' => $username,
            'UserPoolId' => $this->userPoolId,
        ]);
    }


    /**
     * Set the value of boolClientSecret
     */
    public function setBoolClientSecret(): self
    {
        $this->boolClientSecret = true;

        return $this;
    }

    /**
     * Authenticates the provider using the given code and redirect URL.
     *
     * @param string $code The authentication code.
     * @param string $redirectUrl The redirect URL.
     * @param string $scope The scope of the authentication (default: 'email profile openid').
     * @return array The authentication result.
     */
    public function authenticateProvider(string $code, string $redirectUrl, string $scope = 'email profile openid'): array
    {
        $data = array(
            'code' => $code,
            'client_id' => $this->appClientId,
            'client_secret' => $this->appClientSecret,
            'grant_type' => 'authorization_code',
            'scope' => $scope,
            'redirect_uri' => $redirectUrl
        );

        $path = '/oauth2/token' . '?' . http_build_query($data);
        $client = new Client([
            'base_uri' => 'https://budgetcontrol.auth.eu-west-1.amazoncognito.com',
            'headers' => [
                'Content-Type' => 'application/x-www-form-urlencoded'
            ]
        ]);

        $response = $client->request('POST', $path, $data);
        $response = $response->getBody();
        $content = json_decode($response->getContents());

        if(!isset($content['AccessToken'])) {
            throw new Exception('Invalid token', 400);
        }

        return $content;
    }
    

    /**
     * Get the value of provider
     */
    public function provider()
    {
        if(!isset($this->appName)) {
            throw new \Exception('The app name is required');
        }

        return new Provider($this->appClientId, $this->region, $this->appName);
    }


    /**
     * Set the value of appName
     */
    public function setAppName($appName): self
    {
        $this->appName = $appName;

        return $this;
    }
}
