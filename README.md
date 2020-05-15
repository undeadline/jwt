JSON Web Token (JWT)
=========================

This package help you with JWT generating, refreshing, checking.

Composer install

```
composer require undeadline/jwt
```

How to use:

Generate token
```
$payload = ['id' => 1];

$jwt = new \Undeadline\JWT();
$token = $jwt->getToken($payload);

echo $token // +YToyOntzOjM6ImFsZyI7czo2OiJzaGEyNTYiO3M6MzoidHlwIjtzOjM6IkpXVCI7fQ==.YToxOntzOjM6ImV4cCI7aToxNTg5NTQ1ODczO30=.72ee2c0d5b168ca5059765990fffb4f6b672c2f721c5233a179a7ffb8372bcb1
```

Generate refresh token
```
$payload = ['id' => 1];

$jwt = new \Undeadline\JWT();
$refresh_token = $jwt->refreshToken($payload);

echo $refresh_token // c51d702341c5d3de5ca0540648f47a02afc5e117887b59ccf31208bb319d6af8
```

Generate refresh token lifetime
```
$jwt = new \Undeadline\JWT();
$refresh_token_lifetime = $jwt->getRefreshTokenLifetime();

echo $refresh_token_lifetime // 1842927392 => timestamp
```

Token validation
```
$payload = ['id' => 1];

$jwt = new \Undeadline\JWT();
$token = $jwt->getToken($payload);

$valid = $jwt->validateToken($token);

echo $valid // true if valid or false if not valid
```