<?php

namespace undeadline;

class JWT
{
    private static $config;

    public static function generate_token($data)
    {
        self::$config = self::loadConfig();
        $headers = self::headers();
        $payload = $data;

        $body = base64_encode(serialize($headers)) . '.' . base64_encode(serialize($payload));
        $signature = hash_hmac(self::$config['algorithm'], $body, self::$config['secret']);

        return $body . '.' . base64_encode($signature);
    }

    public static function refresh_token()
    {
        // TODO
    }

    public static function check_token($token)
    {
        // TODO
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