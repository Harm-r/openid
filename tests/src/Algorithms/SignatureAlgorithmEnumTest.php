<?php

declare(strict_types=1);

namespace SimpleSAML\Test\OpenID\Algorithms;

use Jose\Component\Core\Exception\MissingDependencyException;
use Jose\Component\KeyManagement\JWKFactory;
use Jose\Component\Signature\Algorithm\EdDSA;
use Jose\Component\Signature\Algorithm\ES256;
use Jose\Component\Signature\Algorithm\ES384;
use Jose\Component\Signature\Algorithm\ES512;
use Jose\Component\Signature\Algorithm\PS256;
use Jose\Component\Signature\Algorithm\PS384;
use Jose\Component\Signature\Algorithm\PS512;
use Jose\Component\Signature\Algorithm\RS256;
use Jose\Component\Signature\Algorithm\RS384;
use Jose\Component\Signature\Algorithm\RS512;
use Jose\Unsecured\Signature\None;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\RequiresPhpExtension;
use PHPUnit\Framework\TestCase;
use SimpleSAML\OpenID\Algorithms\SignatureAlgorithmEnum;

#[CoversClass(SignatureAlgorithmEnum::class)]
final class SignatureAlgorithmEnumTest extends TestCase
{
    #[RequiresPhpExtension('openssl')]
    public function testCanGetProperSignatureAlgorithmInstance(): void
    {
        if (EdDSA::isSupported()) {
            $this->assertInstanceOf(EdDSA::class, SignatureAlgorithmEnum::EdDSA->instance());
        }

        $this->assertInstanceOf(
            ES256::class,
            SignatureAlgorithmEnum::ES256->instance(),
        );
        $this->assertInstanceOf(
            ES384::class,
            SignatureAlgorithmEnum::ES384->instance(),
        );
        $this->assertInstanceOf(
            ES512::class,
            SignatureAlgorithmEnum::ES512->instance(),
        );
        $this->assertInstanceOf(
            None::class,
            SignatureAlgorithmEnum::none->instance(),
        );
        $this->assertInstanceOf(
            PS256::class,
            SignatureAlgorithmEnum::PS256->instance(),
        );
        $this->assertInstanceOf(
            PS384::class,
            SignatureAlgorithmEnum::PS384->instance(),
        );
        $this->assertInstanceOf(
            PS512::class,
            SignatureAlgorithmEnum::PS512->instance(),
        );
        $this->assertInstanceOf(
            RS256::class,
            SignatureAlgorithmEnum::RS256->instance(),
        );
        $this->assertInstanceOf(
            RS384::class,
            SignatureAlgorithmEnum::RS384->instance(),
        );
        $this->assertInstanceOf(
            RS512::class,
            SignatureAlgorithmEnum::RS512->instance(),
        );
    }


    public function testCanCheckEdDSASupport(): void
    {
        if (!EdDSA::isSupported()) {
            $this->assertFalse(SignatureAlgorithmEnum::EdDSA->isSupported());
            $this->expectException(MissingDependencyException::class);
            SignatureAlgorithmEnum::EdDSA->instance();
            return;
        }

        $this->assertTrue(SignatureAlgorithmEnum::EdDSA->isSupported());
        $this->assertInstanceOf(EdDSA::class, SignatureAlgorithmEnum::EdDSA->instance());
    }


    public function testUnsecuredAlgorithmHasNoRuntimeDependencies(): void
    {
        $this->assertTrue(SignatureAlgorithmEnum::none->isSupported());
        $this->assertInstanceOf(None::class, SignatureAlgorithmEnum::none->instance());
    }


    /**
     * @return \Iterator<string, array{\SimpleSAML\OpenID\Algorithms\SignatureAlgorithmEnum}>
     */
    public static function mldsaProvider(): \Iterator
    {
        yield 'ML-DSA-44' => [SignatureAlgorithmEnum::MLDSA44];
        yield 'ML-DSA-65' => [SignatureAlgorithmEnum::MLDSA65];
        yield 'ML-DSA-87' => [SignatureAlgorithmEnum::MLDSA87];
    }


    #[DataProvider('mldsaProvider')]
    public function testMLDSARuntimeSupport(SignatureAlgorithmEnum $algorithm): void
    {
        // Enum parsing and inspection must also work on PHP/OpenSSL versions unable to execute ML-DSA.
        $this->assertSame($algorithm, SignatureAlgorithmEnum::from($algorithm->value));
        $this->assertFalse($algorithm->isNone());

        if (!$algorithm->isSupported()) {
            $this->assertFalse($algorithm->isSupported());
            $this->expectException(MissingDependencyException::class);
            $this->expectExceptionMessage($algorithm->value);
            $this->expectExceptionMessage('requires');
            $algorithm->instance();
            return;
        }

        $this->assertTrue($algorithm->isSupported());
        $instance = $algorithm->instance();
        $this->assertSame($algorithm->value, $instance->name());

        $key = (new JWKFactory())->mldsa($algorithm->value);
        $message = 'ML-DSA runtime capability test';
        $signature = $instance->sign($key, $message);
        $this->assertTrue($instance->verify($key->toPublic(), $message, $signature));
        $this->assertFalse($instance->verify($key->toPublic(), $message . ' changed', $signature));
    }


    public function testIsNone(): void
    {
        $this->assertTrue(SignatureAlgorithmEnum::none->isNone());
        $this->assertFalse(SignatureAlgorithmEnum::EdDSA->isNone());
        $this->assertFalse(SignatureAlgorithmEnum::ES256->isNone());
        $this->assertFalse(SignatureAlgorithmEnum::ES384->isNone());
        $this->assertFalse(SignatureAlgorithmEnum::ES512->isNone());
        $this->assertFalse(SignatureAlgorithmEnum::PS256->isNone());
        $this->assertFalse(SignatureAlgorithmEnum::PS384->isNone());
        $this->assertFalse(SignatureAlgorithmEnum::PS512->isNone());
        $this->assertFalse(SignatureAlgorithmEnum::RS256->isNone());
        $this->assertFalse(SignatureAlgorithmEnum::RS384->isNone());
        $this->assertFalse(SignatureAlgorithmEnum::RS512->isNone());
    }
}
