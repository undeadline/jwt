<?php

namespace undeadline;

class JWT
{
    private $config;
    private $headers;
    private $payload;
    private $signature;

    public function __construct()
    {
        $this->config = $this->loadConfig();
    }

    public function getToken(array $data)
    {
        $headers = $this->buildHeaders();
        $payload = $this->buildPayload($data);

        $body = base64_encode(serialize($headers)) . '.' . base64_encode(serialize($payload));
        $signature = hash_hmac($this->config['algorithm'], $body, $this->config['secret']);

        return $body . '.' . $signature;
    }

    public function refreshToken()
    {
        // TODO
    }

    public function validateToken($token)
    {
        if (
            !$this->tokenParse($token)
            || !$this->tokenSignatureHaveCorrectLength($this->signature)
            || !$this->tokenSignatureIsValid($this->headers, $this->payload, $this->signature)
            || $this->tokenDateExpired($this->payload)
        ) {
            return false;
        }

        return true;
    }

    private function tokenParse($token)
    {
        $parts = explode('.', $token);

        if (count($parts) !== 3)
            return false;

        return list($this->headers, $this->payload, $this->signature) = $parts;
    }

    private function tokenSignatureIsValid($headers, $payload, $signature)
    {
        $body = $headers . '.' . $payload;

        return (hash_hmac($this->config['algorithm'], $body, $this->config['secret'])) === $signature;
    }

    private function tokenSignatureHaveCorrectLength($signature)
    {
        if ($this->config['signature_length'] !== strlen($signature))
            return false;

        return true;
    }

    private function tokenDateExpired($encoded_payload)
    {
        $decode_payload = unserialize(base64_decode($encoded_payload));

        if ((int) $decode_payload['exp'] < time())
            return true;

        return false;
    }

    private function buildHeaders()
    {
        return ["alg" => $this->config['algorithm'], "typ" => $this->config['type']];
    }

    private function buildPayload($payload)
    {
        return array_merge($payload, ["exp" => time() + $this->config['lifetime']]);
    }

    private function loadConfig()
    {
        return require_once 'config.php';
    }
}