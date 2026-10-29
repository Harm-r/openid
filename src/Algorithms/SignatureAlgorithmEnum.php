<?php

declare(strict_types=1);

namespace SimpleSAML\OpenID\Algorithms;

use Jose\Component\Core\Exception\MissingDependencyException;
use Jose\Component\Signature\Algorithm\EdDSA;
use Jose\Component\Signature\Algorithm\ES256;
use Jose\Component\Signature\Algorithm\ES384;
use Jose\Component\Signature\Algorithm\ES512;
use Jose\Component\Signature\Algorithm\MLDSA44;
use Jose\Component\Signature\Algorithm\MLDSA65;
use Jose\Component\Signature\Algorithm\MLDSA87;
use Jose\Component\Signature\Algorithm\PS256;
use Jose\Component\Signature\Algorithm\PS384;
use Jose\Component\Signature\Algorithm\PS512;
use Jose\Component\Signature\Algorithm\RS256;
use Jose\Component\Signature\Algorithm\RS384;
use Jose\Component\Signature\Algorithm\RS512;
use Jose\Component\Signature\Algorithm\SignatureAlgorithm;
use Jose\Unsecured\Signature\None;

enum SignatureAlgorithmEnum: string
{
    case EdDSA = 'EdDSA';

    case ES256 = 'ES256';

    case ES384 = 'ES384';

    case ES512 = 'ES512';

    case MLDSA44 = 'ML-DSA-44';

    case MLDSA65 = 'ML-DSA-65';

    case MLDSA87 = 'ML-DSA-87';

    case none = 'none';

    case PS256 = 'PS256';

    case PS384 = 'PS384';

    case PS512 = 'PS512';

    case RS256 = 'RS256';

    case RS384 = 'RS384';

    case RS512 = 'RS512';


    /**
     * Checks the runtime dependencies enforced by the upstream algorithm constructor.
     *
     * For ML-DSA, the constructor uses the upstream isSupported() probe of PHP's loaded OpenSSL library.
     * This does not enable the algorithm in a SupportedAlgorithms configuration or validate a signing key.
     */
    public function isSupported(): bool
    {
        try {
            $this->instance();
        } catch (MissingDependencyException) {
            return false;
        }

        return true;
    }


    /**
     * @throws \Jose\Component\Core\Exception\MissingDependencyException When runtime support is missing.
     */
    public function instance(): SignatureAlgorithm
    {
        return match ($this) {
            self::EdDSA => new EdDSA(),
            self::ES256 => new ES256(),
            self::ES384 => new ES384(),
            self::ES512 => new ES512(),
            self::MLDSA44 => new MLDSA44(),
            self::MLDSA65 => new MLDSA65(),
            self::MLDSA87 => new MLDSA87(),
            self::none => new None(),
            self::PS256 => new PS256(),
            self::PS384 => new PS384(),
            self::PS512 => new PS512(),
            self::RS256 => new RS256(),
            self::RS384 => new RS384(),
            self::RS512 => new RS512(),
        };
    }


    public function isNone(): bool
    {
        return $this === SignatureAlgorithmEnum::none;
    }
}
