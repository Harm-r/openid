<?php

declare(strict_types=1);

namespace SimpleSAML\Test\OpenID;

use Jose\Component\Core\Exception\MissingDependencyException;
use Jose\Component\Core\Exception\UnsupportedAlgorithmException;
use Jose\Component\KeyManagement\JWKFactory;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\TestCase;
use SimpleSAML\OpenID\Algorithms\AlgorithmManagerDecorator;
use SimpleSAML\OpenID\Algorithms\SignatureAlgorithmBag;
use SimpleSAML\OpenID\Algorithms\SignatureAlgorithmEnum;
use SimpleSAML\OpenID\Factories\AlgorithmManagerDecoratorFactory;
use SimpleSAML\OpenID\Factories\JwsSerializerManagerDecoratorFactory;
use SimpleSAML\OpenID\Jwk\JwkDecorator;
use SimpleSAML\OpenID\Jwks\Factories\JwksDecoratorFactory;
use SimpleSAML\OpenID\Jws;
use SimpleSAML\OpenID\Jws\Factories\JwsDecoratorBuilderFactory;
use SimpleSAML\OpenID\Jws\Factories\JwsVerifierDecoratorFactory;
use SimpleSAML\OpenID\Jws\JwsDecorator;
use SimpleSAML\OpenID\Jws\JwsDecoratorBuilder;
use SimpleSAML\OpenID\Jws\JwsVerifierDecorator;
use SimpleSAML\OpenID\Serializers\JwsSerializerManagerDecorator;
use SimpleSAML\OpenID\SupportedAlgorithms;
use SimpleSAML\OpenID\SupportedSerializers;

#[CoversClass(Jws::class)]
#[UsesClass(AlgorithmManagerDecorator::class)]
#[UsesClass(AlgorithmManagerDecoratorFactory::class)]
#[UsesClass(SignatureAlgorithmBag::class)]
#[UsesClass(SignatureAlgorithmEnum::class)]
#[UsesClass(JwsSerializerManagerDecoratorFactory::class)]
#[UsesClass(JwsDecoratorBuilderFactory::class)]
#[UsesClass(JwsVerifierDecoratorFactory::class)]
#[UsesClass(JwsDecoratorBuilder::class)]
#[UsesClass(JwsVerifierDecorator::class)]
#[UsesClass(JwsSerializerManagerDecorator::class)]
#[UsesClass(JwsDecorator::class)]
#[UsesClass(JwkDecorator::class)]
#[UsesClass(JwksDecoratorFactory::class)]
#[UsesClass(SupportedAlgorithms::class)]
#[UsesClass(SupportedSerializers::class)]
final class MLDSATest extends TestCase
{
    /**
     * @return \Iterator<string, array{\SimpleSAML\OpenID\Algorithms\SignatureAlgorithmEnum}>
     */
    public static function algorithmProvider(): \Iterator
    {
        yield 'ML-DSA-44' => [SignatureAlgorithmEnum::MLDSA44];
        yield 'ML-DSA-65' => [SignatureAlgorithmEnum::MLDSA65];
        yield 'ML-DSA-87' => [SignatureAlgorithmEnum::MLDSA87];
    }


    #[DataProvider('algorithmProvider')]
    public function testCanBuildSerializeParseAndVerifyJws(SignatureAlgorithmEnum $algorithm): void
    {
        if (!$algorithm->isSupported()) {
            $this->markTestSkipped(sprintf('%s is not supported by this PHP/OpenSSL runtime.', $algorithm->value));
        }

        $key = (new JWKFactory())->mldsa($algorithm->value, [
            'kid' => 'mldsa-integration-test',
            'use' => 'sig',
        ]);
        $jws = new Jws(new SupportedAlgorithms(new SignatureAlgorithmBag($algorithm)));

        $unsigned = $jws->jwsDecoratorBuilder()->fromData(
            new JwkDecorator($key),
            $algorithm,
            ['sub' => 'mldsa-integration-test', 'message' => 'hello from OpenID Tools'],
            ['kid' => 'mldsa-integration-test'],
        );
        $serialized = $jws->jwsSerializerManagerDecorator()->serialize('jws_compact', $unsigned);
        $parsed = $jws->jwsDecoratorBuilder()->fromToken($serialized);

        $this->assertSame($algorithm->value, $parsed->jws()->getSignature(0)->getProtectedHeaderParameter('alg'));
        $this->assertTrue($jws->jwsVerifierDecorator()->verifyWithKeySet(
            $parsed,
            $jws->jwksDecoratorFactory()->fromKeySetData([
                'keys' => [$key->toPublic()->all()],
            ]),
            0,
        ));

        $segments = explode('.', $serialized);
        $signature = $segments[2];
        $segments[2] = ($signature[0] === 'A' ? 'B' : 'A') . substr($signature, 1);
        $tampered = $jws->jwsDecoratorBuilder()->fromToken(implode('.', $segments));

        $this->assertFalse($jws->jwsVerifierDecorator()->verifyWithKeySet(
            $tampered,
            $jws->jwksDecoratorFactory()->fromKeySetData([
                'keys' => [$key->toPublic()->all()],
            ]),
            0,
        ));
    }


    #[DataProvider('algorithmProvider')]
    public function testExplicitConfigurationFailsClearlyWhenRuntimeDoesNotSupportMLDSA(
        SignatureAlgorithmEnum $algorithm,
    ): void {
        if ($algorithm->isSupported()) {
            $this->markTestSkipped('This test requires a PHP/OpenSSL runtime without ML-DSA support.');
        }

        $this->expectException(MissingDependencyException::class);
        $this->expectExceptionMessage('ML-DSA');

        (new AlgorithmManagerDecoratorFactory())->build(
            new SupportedAlgorithms(new SignatureAlgorithmBag($algorithm)),
        );
    }


    #[DataProvider('algorithmProvider')]
    public function testVerifierRejectsADifferentPrivateKeyForTheSameAlgorithm(SignatureAlgorithmEnum $algorithm): void
    {
        if (!$algorithm->isSupported()) {
            $this->markTestSkipped(sprintf('%s is not supported by this PHP/OpenSSL runtime.', $algorithm->value));
        }

        $signingKey = (new JWKFactory())->mldsa($algorithm->value);
        $otherKey = (new JWKFactory())->mldsa($algorithm->value);
        $jws = new Jws(new SupportedAlgorithms(new SignatureAlgorithmBag($algorithm)));
        $serialized = $jws->jwsSerializerManagerDecorator()->serialize(
            'jws_compact',
            $jws->jwsDecoratorBuilder()->fromData(
                new JwkDecorator($signingKey),
                $algorithm,
                ['sub' => 'mismatched-key-test'],
                [],
            ),
        );

        $this->assertFalse($jws->jwsVerifierDecorator()->verifyWithKeySet(
            $jws->jwsDecoratorBuilder()->fromToken($serialized),
            $jws->jwksDecoratorFactory()->fromKeySetData([
                'keys' => [$otherKey->toPublic()->all()],
            ]),
            0,
        ));
    }


    public function testVerifierRejectsAProtectedAlgorithmThatDoesNotMatchTheKey(): void
    {
        if (!SignatureAlgorithmEnum::MLDSA44->isSupported()) {
            $this->markTestSkipped('ML-DSA is not supported by this PHP/OpenSSL runtime.');
        }

        $key = (new JWKFactory())->mldsa(SignatureAlgorithmEnum::MLDSA44->value);
        $algorithms = new SignatureAlgorithmBag(
            SignatureAlgorithmEnum::MLDSA44,
            SignatureAlgorithmEnum::MLDSA65,
        );
        $jws = new Jws(new SupportedAlgorithms($algorithms));
        $serialized = $jws->jwsSerializerManagerDecorator()->serialize(
            'jws_compact',
            $jws->jwsDecoratorBuilder()->fromData(
                new JwkDecorator($key),
                SignatureAlgorithmEnum::MLDSA44,
                ['sub' => 'protected-algorithm-mismatch-test'],
                [],
            ),
        );
        $segments = explode('.', $serialized);
        $header = json_decode(
            base64_decode(strtr($segments[0], '-_', '+/'), true),
            true,
            512,
            JSON_THROW_ON_ERROR,
        );
        $header['alg'] = SignatureAlgorithmEnum::MLDSA65->value;
        $segments[0] = rtrim(strtr(base64_encode(json_encode($header, JSON_THROW_ON_ERROR)), '+/', '-_'), '=');
        $tampered = $jws->jwsDecoratorBuilder()->fromToken(implode('.', $segments));

        $this->assertFalse($jws->jwsVerifierDecorator()->verifyWithKeySet(
            $tampered,
            $jws->jwksDecoratorFactory()->fromKeySetData([
                'keys' => [$key->toPublic()->all()],
            ]),
            0,
        ));
    }


    #[DataProvider('algorithmProvider')]
    public function testVerifierRejectsAnUnregisteredMLDSAAlgorithm(SignatureAlgorithmEnum $algorithm): void
    {
        if (!$algorithm->isSupported()) {
            $this->markTestSkipped(sprintf('%s is not supported by this PHP/OpenSSL runtime.', $algorithm->value));
        }

        $key = (new JWKFactory())->mldsa($algorithm->value);
        $signingJws = new Jws(new SupportedAlgorithms(new SignatureAlgorithmBag($algorithm)));
        $serialized = $signingJws->jwsSerializerManagerDecorator()->serialize(
            'jws_compact',
            $signingJws->jwsDecoratorBuilder()->fromData(
                new JwkDecorator($key),
                $algorithm,
                ['sub' => 'unregistered-algorithm-test'],
                [],
            ),
        );

        $verifier = new Jws();
        $parsed = $verifier->jwsDecoratorBuilder()->fromToken($serialized);

        $this->expectException(UnsupportedAlgorithmException::class);
        $verifier->jwsVerifierDecorator()->verifyWithKeySet(
            $parsed,
            $verifier->jwksDecoratorFactory()->fromKeySetData([
                'keys' => [$key->toPublic()->all()],
            ]),
            0,
        );
    }
}
