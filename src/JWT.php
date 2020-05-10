<?php

namespace undeadline;

class JWT
{
    private static $config;
    private static $headers;
    private static $payload;
    private static $signature;

    public static function getToken($data)
    {
        self::$config = self::loadConfig();
        $headers = self::headers();
        $payload = array_merge($data, ["exp" => time() + self::$config['lifetime']]);

        $body = base64_encode(serialize($headers)) . '.' . base64_encode(serialize($payload));
        $signature = hash_hmac(self::$config['algorithm'], $body, self::$config['secret']);

        return $body . '.' . $signature;
    }

    public static function refreshToken()
    {
        // TODO
    }

    public static function validateToken($token)
    {
        if (!self::tokenParse($token))
            return false;

        self::$config = self::loadConfig();

        if (!self::tokenSignatureIsCorrectLength(self::$signature))
            return false;

        if (!self::tokenSignatureIsValid(self::$headers, self::$payload, self::$signature))
            return false;

        if (self::tokenDateExpired(self::$payload))
            return false;

        return true;
    }

    private static function tokenParse($token)
    {
        $parts = explode('.', $token);

        if (count($parts) !== 3)
            return false;

        return list(self::$headers, self::$payload, self::$signature) = $parts;
    }

    private static function tokenSignatureIsValid($headers, $payload, $signature)
    {
        $body = $headers . '.' . $payload;

        return (hash_hmac(self::$config['algorithm'], $body, self::$config['secret'])) === $signature;
    }

    private static function tokenSignatureIsCorrectLength($signature)
    {
        if (self::$config['signature_length'] !== strlen($signature))
            return false;

        return true;
    }

    private static function tokenDateExpired($encoded_payload)
    {
        $decode_payload = unserialize(base64_decode($encoded_payload));

        if ((int) $decode_payload['exp'] < time())
            return true;

        return false;
    }

    private static function headers()
    {
        return ["alg" => self::$config['algorithm'], "typ" => self::$config['type']];
    }

    private static function loadConfig()
    {
        return require_once 'config.php';
    }
}