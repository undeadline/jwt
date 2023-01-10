<?php

return [
    // Use sha512 algorithm if your OS is have 64bit architecture
    "algorithm" => "SHA512",

    // Alias for header algorithm
    "alg" => "HS512",

    "type" => "JWT",

    // Your secret string for hashing sign
    "access_secret" => '14b2478cc1854f5075a9bd6e14526dc802258c438ac4f7a257819612f8669c9d',

    // Your refresh string for hashing sign
    "refresh_secret" => '6548311984d74d6b9a9161477069d46471aa9a01abb3d53c63e59be73050a04b'
];