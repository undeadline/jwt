<?php

return [
    // Use sha512 algorithm if your OS is have 64bit architecture
    "algorithm" => "sha256",
    // Hash length is depends from algorithm
    "signature_length" => 64,
    "type" => "JWT",
    // Your secret string for hashing sign
    "secret" => 123,
    // Count of seconds for token lifetime
    "lifetime" => 360
];