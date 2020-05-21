<?php

namespace Undeadline;

class JWT
{
    /**
     * Store config file
     *
     * @var mixed
     */
    protected $config;

    /**
     * Store encoded headers as base64 string from incoming token
     *
     * @var
     */
    protected $headers;
    /**
     * Store encoded payload as base64 string from incoming token
     *
     * @var
     */
    protected $payload;

    /**
     * Store signature string from incoming token
     *
     * @var
     */
    protected $signature;

    /**
     * JWT constructor.
     */
    public function __construct()
    {
        $this->config = $this->loadConfig();
    }

    /**
     * Generate access token
     *
     * @param array $data
     * @return string
     */
    public function getToken(array $data = []): string
    {
        $headers = $this->buildHeaders();
        $payload = $this->buildPayload($data);

        $body = base64_encode(serialize($headers)) . '.' . base64_encode(serialize($payload));
        $signature = hash_hmac($this->config['algorithm'], $body, $this->config['secret']);

        return $body . '.' . $signature;
    }

    public function getPayload()
    {
        return $this->payload ? unserialize(base64_decode($this->payload)) : [];
    }

    /**
     * Generate refresh token
     *
     * @param array $data
     * @return string
     */
    public function refreshToken(array $data = []): string
    {
        return hash_hmac($this->config['algorithm'], base64_encode(serialize($data) . time()), $this->config['refresh_secret']);
    }

    /**
     * Return lifetime of refresh token as timestamp
     *
     * @return int
     */
    public function getRefreshTokenLifetime(): int
    {
        return time() + $this->config['refresh_token_lifetime'];
    }

    /**
     * Validation incoming token
     *
     * @param string $token
     * @return bool
     */
    public function validateToken(string $token): bool
    {
        if (
            !$this->parseToken($token)
            || !$this->tokenSignatureHaveCorrectLength($this->signature)
            || !$this->tokenSignatureIsValid($this->headers, $this->payload, $this->signature)
            || $this->tokenDateExpired($this->payload)
        ) {
            return false;
        }

        return true;
    }

    /**
     * Parsing incoming token on parts and check that have 3 parts
     *
     * @param string $token
     * @return bool
     */
    protected function parseToken(string $token): bool
    {
        $parts = explode('.', $token);

        if (count($parts) !== 3)
            return false;

        list($this->headers, $this->payload, $this->signature) = $parts;

        return true;
    }

    /**
     * Validation signature incoming token
     *
     * @param string $headers
     * @param string $payload
     * @param string $signature
     * @return bool
     */
    protected function tokenSignatureIsValid(string $headers, string $payload, string $signature): bool
    {
        $body = $headers . '.' . $payload;

        return (hash_hmac($this->config['algorithm'], $body, $this->config['secret'])) === $signature;
    }

    /**
     * Validation what signature is have correct length
     *
     * @param string $signature
     * @return bool
     */
    protected function tokenSignatureHaveCorrectLength(string $signature)
    {
        if ($this->config['signature_length'] !== strlen($signature))
            return false;

        return true;
    }

    /**
     * Validation if access token lifetime is expired
     *
     * @param string $encoded_payload
     * @return bool
     */
    protected function tokenDateExpired(string $encoded_payload): bool
    {
        $decode_payload = unserialize(base64_decode($encoded_payload));

        if ((int) $decode_payload['exp'] < time())
            return true;

        return false;
    }

    /**
     * Return array of headers token
     *
     * @return array
     */
    protected function buildHeaders(): array
    {
        return ["alg" => $this->config['algorithm'], "typ" => $this->config['type']];
    }

    /**
     * Return array of payload
     *
     * @param array $payload
     * @return array
     */
    protected function buildPayload(array $payload): array
    {
        return array_merge($payload, ["exp" => time() + $this->config['lifetime']]);
    }

    /**
     * Load config file
     *
     * @return mixed
     */
    private function loadConfig()
    {
        return require 'config.php';
    }
}