<?php
/** @var \malirobot\AwsCognito\CognitoClient $client */
$client = require(__DIR__ . '/bootstrap.php');

$username = 'test@example.com';
$refreshToken = 'refresh-token';

$refreshResponse = $client->refreshAuthentication($username, $refreshToken);
