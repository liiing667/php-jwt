<?php

namespace Firebase\JWT;

use DomainException;
use PHPUnit\Framework\TestCase;
use UnexpectedValueException;

class Uid34390JwtAlgorithmPolicyTest extends TestCase
{
    protected function tearDown(): void
    {
        Uid34390KeySwitchingJWT::$key = null;
        Uid34390KeySwitchingJWT::$switched = false;
    }

    public function testAlgorithmMismatchIsRejectedOnEveryAttempt()
    {
        $privateKey = openssl_pkey_new([
            'digest_alg' => 'sha256',
            'private_key_bits' => 2048,
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
        ]);
        $this->assertNotFalse($privateKey);

        $publicKey = openssl_pkey_get_details($privateKey)['key'];
        $jwt = JWT::encode(['sub' => 'mismatch'], $privateKey, 'RS256');
        $key = new Key($publicKey, 'ES256');

        foreach ([1, 2] as $attempt) {
            try {
                JWT::decode($jwt, $key);
                $this->fail('Algorithm mismatch must not succeed on attempt ' . $attempt);
            } catch (UnexpectedValueException $e) {
                $this->assertSame('Incorrect key for this algorithm', $e->getMessage());
            }
        }
    }

    public function testKeyFamilyCannotBeUsedAsAnotherAlgorithm()
    {
        $privateKey = openssl_pkey_new([
            'digest_alg' => 'sha256',
            'private_key_bits' => 2048,
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
        ]);
        $this->assertNotFalse($privateKey);
        $publicKey = openssl_pkey_get_details($privateKey)['key'];

        $signingInput = JWT::urlsafeB64Encode('{"typ":"JWT","alg":"ES256"}')
            . '.' . JWT::urlsafeB64Encode('{"sub":"family-confusion"}');
        $this->assertTrue(openssl_sign($signingInput, $signature, $privateKey, 'SHA256'));
        $jwt = $signingInput . '.' . JWT::urlsafeB64Encode($signature);

        $this->expectException(UnexpectedValueException::class);
        $this->expectExceptionMessage('Incorrect key for this algorithm');
        JWT::decode($jwt, new Key($publicKey, 'ES256'));
    }

    public function testKeyConfiguredForAnotherAlgorithmCannotBeSwitchedDuringDecode()
    {
        $privateKey = openssl_pkey_new([
            'digest_alg' => 'sha256',
            'private_key_bits' => 2048,
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
        ]);
        $this->assertNotFalse($privateKey);
        $publicKey = openssl_pkey_get_details($privateKey)['key'];

        $jwt = JWT::encode(['sub' => 'key-retry'], $privateKey, 'RS256');
        $key = new Uid34390AlgorithmSwitchingKey($publicKey, 'ES256');
        Uid34390KeySwitchingJWT::$key = $key;

        try {
            Uid34390KeySwitchingJWT::decode($jwt, $key);
            $this->fail('A key switched during decode must not become accepted');
        } catch (UnexpectedValueException $e) {
            $this->assertSame('Incorrect key for this algorithm', $e->getMessage());
        }

        $this->assertTrue(Uid34390KeySwitchingJWT::$switched);
        $this->assertSame('RS256', $key->getAlgorithm());
    }

    /**
     * @runInSeparateProcess
     */
    public function testAlgorithmRegistryCannotBeRemappedWhileDecoding()
    {
        $secret = str_repeat('k', 32);
        $signingInput = JWT::urlsafeB64Encode('{"typ":"JWT","alg":"RS256"}')
            . '.' . JWT::urlsafeB64Encode('{"sub":"registry-confusion"}');
        $signature = hash_hmac('sha256', $signingInput, $secret, true);
        $jwt = $signingInput . '.' . JWT::urlsafeB64Encode($signature);

        $this->expectException(DomainException::class);
        $this->expectExceptionMessage('OpenSSL unable to validate key');
        Uid34390AlgorithmRemappingJWT::decode($jwt, new Key($secret, 'RS256'));
    }
}

class Uid34390AlgorithmRemappingJWT extends JWT
{
    public static function urlsafeB64Decode(string $input): string
    {
        $decoded = parent::urlsafeB64Decode($input);

        // Simulate an in-flight retry/config change. The snapshot taken by
        // decode() must keep using the original RS256 policy.
        JWT::$supported_algs['RS256'] = ['hash_hmac', 'SHA256'];

        return $decoded;
    }
}

class Uid34390AlgorithmSwitchingKey extends Key
{
    private string $effectiveAlgorithm;

    public function __construct(
        #[\SensitiveParameter] $keyMaterial,
        string $algorithm
    ) {
        parent::__construct($keyMaterial, $algorithm);
        $this->effectiveAlgorithm = $algorithm;
    }

    public function switchAlgorithm(string $algorithm): void
    {
        $this->effectiveAlgorithm = $algorithm;
    }

    public function getAlgorithm(): string
    {
        return $this->effectiveAlgorithm;
    }
}

class Uid34390KeySwitchingJWT extends JWT
{
    /** @var null|Uid34390AlgorithmSwitchingKey */
    public static $key = null;

    /** @var bool */
    public static $switched = false;

    public static function urlsafeB64Decode(string $input): string
    {
        $decoded = parent::urlsafeB64Decode($input);
        if (!self::$switched && null !== self::$key) {
            self::$key->switchAlgorithm('RS256');
            self::$switched = true;
        }

        return $decoded;
    }
}
