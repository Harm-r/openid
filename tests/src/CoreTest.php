<?php

declare(strict_types=1);

namespace SimpleSAML\Test\OpenID;

use DateInterval;
use Jose\Component\KeyManagement\JWKFactory;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\TestCase;
use Psr\Log\LoggerInterface;
use SimpleSAML\OpenID\Algorithms\AlgorithmManagerDecorator;
use SimpleSAML\OpenID\Algorithms\SignatureAlgorithmBag;
use SimpleSAML\OpenID\Algorithms\SignatureAlgorithmEnum;
use SimpleSAML\OpenID\Core;
use SimpleSAML\OpenID\Core\Factories\ClientAssertionFactory;
use SimpleSAML\OpenID\Core\Factories\IdTokenFactory;
use SimpleSAML\OpenID\Core\Factories\IdTokenHintFactory;
use SimpleSAML\OpenID\Core\Factories\LogoutTokenFactory;
use SimpleSAML\OpenID\Core\Factories\RequestObjectFactory;
use SimpleSAML\OpenID\Decorators\DateIntervalDecorator;
use SimpleSAML\OpenID\Factories\AlgorithmManagerDecoratorFactory;
use SimpleSAML\OpenID\Factories\ClaimFactory;
use SimpleSAML\OpenID\Factories\DateIntervalDecoratorFactory;
use SimpleSAML\OpenID\Factories\JwsSerializerManagerDecoratorFactory;
use SimpleSAML\OpenID\Jwk\JwkDecorator;
use SimpleSAML\OpenID\Jws\Factories\JwsDecoratorBuilderFactory;
use SimpleSAML\OpenID\Jws\Factories\JwsVerifierDecoratorFactory;
use SimpleSAML\OpenID\Jws\Factories\ParsedJwsFactory;
use SimpleSAML\OpenID\Jws\JwsDecoratorBuilder;
use SimpleSAML\OpenID\Jws\JwsVerifierDecorator;
use SimpleSAML\OpenID\Serializers\JwsSerializerManagerDecorator;
use SimpleSAML\OpenID\SupportedAlgorithms;
use SimpleSAML\OpenID\SupportedSerializers;

#[CoversClass(Core::class)]
#[UsesClass(ParsedJwsFactory::class)]
#[UsesClass(SignatureAlgorithmBag::class)]
#[UsesClass(SignatureAlgorithmEnum::class)]
#[UsesClass(SupportedAlgorithms::class)]
#[UsesClass(JwkDecorator::class)]
#[UsesClass(\SimpleSAML\OpenID\Core\RequestObject::class)]
#[UsesClass(RequestObjectFactory::class)]
#[UsesClass(ClientAssertionFactory::class)]
#[UsesClass(DateIntervalDecorator::class)]
#[UsesClass(DateIntervalDecoratorFactory::class)]
#[UsesClass(AlgorithmManagerDecoratorFactory::class)]
#[UsesClass(JwsSerializerManagerDecoratorFactory::class)]
#[UsesClass(JwsDecoratorBuilderFactory::class)]
#[UsesClass(JwsVerifierDecoratorFactory::class)]
#[UsesClass(JwsDecoratorBuilder::class)]
#[UsesClass(AlgorithmManagerDecorator::class)]
#[UsesClass(JwsVerifierDecorator::class)]
#[UsesClass(JwsSerializerManagerDecorator::class)]
#[UsesClass(ClaimFactory::class)]
#[UsesClass(IdTokenFactory::class)]
#[UsesClass(IdTokenHintFactory::class)]
#[UsesClass(LogoutTokenFactory::class)]
final class CoreTest extends TestCase
{
    /**
     * @var \PHPUnit\Framework\MockObject\Stub&\SimpleSAML\OpenID\SupportedAlgorithms
     */
    protected \PHPUnit\Framework\MockObject\Stub $supportedAlgorithmsMock;

    /**
     * @var \PHPUnit\Framework\MockObject\Stub&\SimpleSAML\OpenID\SupportedSerializers
     */
    protected \PHPUnit\Framework\MockObject\Stub $supportedSerializerMock;

    protected DateInterval $timestampValidationLeeway;

    /**
     * @var \PHPUnit\Framework\MockObject\Stub&\Psr\Log\LoggerInterface
     */
    protected \PHPUnit\Framework\MockObject\Stub $loggerMock;


    protected function setUp(): void
    {
        $this->supportedAlgorithmsMock = $this->createStub(SupportedAlgorithms::class);
        $this->supportedSerializerMock = $this->createStub(SupportedSerializers::class);
        $this->timestampValidationLeeway = new DateInterval('PT1M');
        $this->loggerMock = $this->createStub(LoggerInterface::class);
    }


    protected function sut(
        ?SupportedAlgorithms $supportedAlgorithms = null,
        ?SupportedSerializers $supportedSerializers = null,
        ?DateInterval $timestampValidationLeeway = null,
        ?LoggerInterface $logger = null,
    ): Core {
        $supportedAlgorithms ??= $this->supportedAlgorithmsMock;
        $supportedSerializers ??= $this->supportedSerializerMock;
        $timestampValidationLeeway ??= $this->timestampValidationLeeway;
        $logger ??= $this->loggerMock;

        return new Core(
            $supportedAlgorithms,
            $supportedSerializers,
            $timestampValidationLeeway,
            $logger,
        );
    }


    public function testCanCreateInstance(): void
    {
        $this->assertInstanceOf(
            Core::class,
            $this->sut(),
        );
    }


    /**
     * @return \Iterator<string, array{\SimpleSAML\OpenID\Algorithms\SignatureAlgorithmEnum}>
     */
    public static function mldsaAlgorithmProvider(): \Iterator
    {
        yield 'ML-DSA-44' => [SignatureAlgorithmEnum::MLDSA44];
        yield 'ML-DSA-65' => [SignatureAlgorithmEnum::MLDSA65];
        yield 'ML-DSA-87' => [SignatureAlgorithmEnum::MLDSA87];
    }


    #[DataProvider('mldsaAlgorithmProvider')]
    public function testConfiguredMLDSAWorksForOpenIdRequestObjects(SignatureAlgorithmEnum $algorithm): void
    {
        if (!$algorithm->isSupported()) {
            $this->markTestSkipped(sprintf('%s is not supported by this PHP/OpenSSL runtime.', $algorithm->value));
        }

        $core = new Core(new SupportedAlgorithms(new SignatureAlgorithmBag($algorithm)));
        $key = (new JWKFactory())->mldsa($algorithm->value);
        $factory = $core->requestObjectFactory();
        $requestObject = $factory->fromData(
            new JwkDecorator($key),
            $algorithm,
            [
                'iss' => 'client.example',
                'aud' => 'https://issuer.example',
                'iat' => time(),
                'exp' => time() + 60,
            ],
            [],
        );

        $parsed = $factory->fromToken($requestObject->getToken());
        $parsed->verifyWithKey($key->toPublic()->all());

        $this->assertSame($algorithm->value, $parsed->getAlgorithm());
    }


    public function testCanBuildTools(): void
    {
        $sut = $this->sut();

        $this->assertInstanceOf(
            RequestObjectFactory::class,
            $sut->requestObjectFactory(),
        );

        $this->assertInstanceOf(
            ClientAssertionFactory::class,
            $sut->clientAssertionFactory(),
        );

        $this->assertInstanceOf(
            IdTokenFactory::class,
            $sut->idTokenFactory(),
        );

        $this->assertInstanceOf(
            IdTokenHintFactory::class,
            $sut->idTokenHintFactory(),
        );

        $this->assertInstanceOf(
            LogoutTokenFactory::class,
            $sut->logoutTokenFactory(),
        );
    }
}
