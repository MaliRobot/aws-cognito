<?php
/** @var \malirobot\AwsCognito\CognitoClient $client */
$client = require(__DIR__ . '/bootstrap.php');

$accessToken = '';

$username = $client->verifyAccessToken($accessToken);
