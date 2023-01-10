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
     * The "iss" (issuer) claim identifies the principal that issued the
     * JWT.  The processing of this claim is generally application specific.
     * The "iss" value is a case-sensitive string containing a StringOrURI
     * value.  Use of this claim is OPTIONAL.
     */
    protected $issuer;

    /**
     * The "sub" (subject) claim identifies the principal that is the
     * subject of the JWT.  The claims in a JWT are normally statements
     * about the subject.  The subject value MUST either be scoped to be
     * locally unique in the context of the issuer or be globally unique.
     * The processing of this claim is generally application specific.  The
     * "sub" value is a case-sensitive string containing a StringOrURI
     * value.  Use of this claim is OPTIONAL.
     */
    protected $subject;

    /**
     * The "aud" (audience) claim identifies the recipients that the JWT is
     * intended for.  Each principal intended to process the JWT MUST
     * identify itself with a value in the audience claim.  If the principal
     * processing the claim does not identify itself with a value in the
     * "aud" claim when this claim is present, then the JWT MUST be
     * rejected.  In the general case, the "aud" value is an array of case-
     * sensitive strings, each containing a StringOrURI value.  In the
     * special case when the JWT has one audience, the "aud" value MAY be a
     * single case-sensitive string containing a StringOrURI value.  The
     * interpretation of audience values is generally application specific.
     * Use of this claim is OPTIONAL.
     */
    protected $audience;

    /**
     * The "exp" (expiration time) claim identifies the expiration time on
     * or after which the JWT MUST NOT be accepted for processing.  The
     * processing of the "exp" claim requires that the current date/time
     * MUST be before the expiration date/time listed in the "exp" claim.
     * Implementers MAY provide for some small leeway, usually no more than
     * a few minutes, to account for clock skew.  Its value MUST be a number
     * containing a NumericDate value.  Use of this claim is OPTIONAL.
     */
    protected $expiration;

    /**
     * The "nbf" (not before) claim identifies the time before which the JWT
     * (MUST NOT be accepted for processing.  The processing of the "nbf"
     * claim requires that the current date/time MUST be after or equal to
     * the not-before date/time listed in the "nbf" claim.  Implementers MAY
     * provide for some small leeway, usually no more than a few minutes, to
     * account for clock skew.  Its value MUST be a number containing a
     * NumericDate value.  Use of this claim is OPTIONAL.
     */
    protected $notBefore;

    /**
     * The "jti" (JWT ID) claim provides a unique identifier for the JWT.
     * The identifier value MUST be assigned in a manner that ensures that
     * there is a negligible probability that the same value will be
     * accidentally assigned to a different data object; if the application
     * uses multiple issuers, collisions MUST be prevented among values
     * produced by different issuers as well.  The "jti" claim can be used
     * to prevent the JWT from being replayed.  The "jti" value is a case-
     * sensitive string.  Use of this claim is OPTIONAL.
     */
    protected $JWTID;

    /**
     * The "iat" (issued at) claim identifies the time at which the JWT was
     * issued.  This claim can be used to determine the age of the JWT.  Its
     * value MUST be a number containing a NumericDate value.  Use of this
     * claim is OPTIONAL.
     */
    protected $issuedAt;

    /**
     * Claims for payload
     */
    protected $claims = [];

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
     * @return string
     */
    public function getAccessToken(): string
    {
        $headers = $this->encodeHeaders($this->buildHeaders());
        $payload = $this->encodePayload($this->buildPayload());
        $signature = $this->makeSignature($headers, $payload);

        return $headers . '.' . $payload . '.' . $signature;
    }

    protected function encode(array $data): string
    {
        return $this->base64UrlEncode(json_encode($data));
    }

    protected function encodeHeaders(array $headers): string
    {
        return $this->encode($headers);
    }

    protected function encodePayload(array $payload): string
    {
        return $this->encode($payload);
    }

    protected function makeSignature(string $headers, string $payload)
    {
        return $this->base64UrlEncode(hash_hmac($this->config['algorithm'], $headers . '.' . $payload, $this->config['access_secret'], true));
    }

    public function getPayload()
    {
        return $this->payload ? json_decode($this->base64UrlDecode($this->payload)) : [];
    }

    /**
     * Generate refresh token
     *
     * @return string
     */
    public function getRefreshToken(): string
    {
        return hash_hmac(
            $this->config['algorithm'], 
            $this->base64UrlEncode(
                bin2hex(random_bytes(32)) . time()
            ), 
            $this->config['refresh_secret']
        );
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
            !$this->parseToken($token) ||
            !$this->tokenSignatureIsValid($this->headers, $this->payload, $this->signature) ||
            $this->tokenDateExpired($this->payload)
        ) {
            return false;
        }

        return true;
    }

    /**
     * Set claims in payload
     *
     * @param array $claims
     * @return void
     */
    public function setClaims(array $claims): void
    {
        $this->claims = $claims;
    }

    /**
     * Set issuer in payload
     *
     * @param string $issuer
     * @return void
     */
    public function setIssuer(string $issuer): void
    {
        $this->issuer = $issuer;
    }

    /**
     * Set subject in payload
     *
     * @param string $subject
     * @return void
     */
    public function setSubject(string $subject): void
    {
        $this->subject = $subject;
    }

    /**
     * Set audience in payload
     *
     * @param string $audience
     * @return void
     */
    public function setAudience(string $audience): void
    {
        $this->audience = $audience;
    }

    /**
     * Set expxration in payload
     *
     * @param int $expxration
     * @return void
     */
    public function setExpirationTime(int $expiration): void
    {
        $this->expiration = $expiration;
    }

    /**
     * Set not before in payload
     *
     * @param int $notBefore
     * @return void
     */
    public function setNotBeforeTime(int $notBefore): void
    {
        $this->notBefore = $notBefore;
    }

    /**
     * Set issued at in payload
     *
     * @param int $issuedAt
     * @return void
     */
    public function setIssuedTime(int $issuedAt): void
    {
        $this->issuedAt = $issuedAt;
    }

    /**
     * Set JWTID in payload
     *
     * @param string $JWTID
     * @return void
     */
    public function setJWTID(string $JWTID): void
    {
        $this->JWTID = $JWTID;
    }

    protected function base64UrlEncode(string $data): string
    {
        return str_replace(['+','/','='], ['-','_',''], base64_encode($data));
    }

    protected function base64UrlDecode(string $base64Url): string
    {
        return base64_decode(str_replace(['-','_'], ['+','/'], $base64Url));
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
        return $this->base64UrlEncode(hash_hmac($this->config['algorithm'], $headers . '.' . $payload, $this->config['access_secret'], true)) === $signature;
    }

    /**
     * Validation if access token lifetime is expired
     *
     * @param string $encoded_payload
     * @return bool
     */
    protected function tokenDateExpired(string $encoded_payload): bool
    {
        $decodePayload = json_decode($this->base64UrlDecode($encoded_payload), true);

        if (isset($decodePayload['exp']) && is_numeric($decodePayload['exp']) && (int) $decodePayload['exp'] < time())
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
        return ["alg" => $this->config['alg'], "typ" => $this->config['type']];
    }

    /**
     * Return array of payload
     *
     * @return array
     */
    protected function buildPayload(): array
    {
        $payload = [];

        $this->issuer ? $payload["iss"] = $this->issuer : null;
        $this->subject ? $payload["sub"] = $this->subject : null;
        $this->audience ? $payload["aud"] = $this->audience : null;
        $this->expiration ? $payload["exp"] = $this->expiration : null;
        $this->notBefore ? $payload["nbf"] = $this->notBefore : null;
        $this->issuedAt ? $payload["iat"] = $this->issuedAt : null;
        $this->JWTID ? $payload["jti"] = $this->JWTID : null;
        
        foreach($this->claims as $claim => $value) {
            $payload[$claim] = $value;
        }

        return $payload;
    }

    /**
     * Load config file
     *
     * @return mixed
     */
    private function loadConfig()
    {
        return include 'config.php';
    }
}