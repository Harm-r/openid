# OpenID Tools Library Installation

Library can be installed by using Composer:

```shell
composer require simplesamlphp/openid
```

## ML-DSA runtime support

ML-DSA requires `web-token/jwt-library` 4.3.0 or later. Until 4.3.0 is
released, this library targets its `4.3.x-dev` development branch (the upstream
`master` branch). PHP 8.4 or later and PHP's loaded OpenSSL library must provide
ML-DSA (OpenSSL 3.5 or later). Existing algorithms remain usable on PHP 8.2/8.3
when their own runtime dependencies are available. Composer stability settings
are root-only: applications consuming this development version must allow the
required development package, for example with `minimum-stability: dev` and
`prefer-stable: true`.

Check availability before offering an algorithm to a caller:

```php
use SimpleSAML\OpenID\Algorithms\SignatureAlgorithmEnum;

$algorithm = SignatureAlgorithmEnum::MLDSA44;
if (!$algorithm->isSupported()) {
    throw new \RuntimeException('ML-DSA-44 is unavailable in this PHP runtime.');
}
```

`isSupported()` uses the upstream constructor's dependency checks. For ML-DSA,
these call its runtime capability probe; they do not rely on the system `openssl`
command or just a version string. The check does not register the algorithm in
`SupportedAlgorithms`, authorize its use, or validate a key.

Calling `instance()` directly still throws the upstream
`Jose\Component\Core\Exception\MissingDependencyException` with the missing
requirement when ML-DSA is unavailable. No alternative algorithm is selected.

Algorithm policy is still explicit. `Core` and `RequestObject` default to `none`
and `RS256`; adding ML-DSA to the library does not silently enable it for those
flows. Supply a `SupportedAlgorithms` instance with the ML-DSA variants your
application allows. Federation, VC, and Token Status List factories likewise
take the signing algorithm as an explicit argument.
