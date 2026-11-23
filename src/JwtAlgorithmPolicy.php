<?php

namespace Firebase\JWT;

use DomainException;
use InvalidArgumentException;
use UnexpectedValueException;

/**
 * Immutable algorithm/key policy for one JWT decode transaction.
 *
 * The header algorithm, the key algorithm, the key material and the key length
 * are all resolved once. Signature verification then uses only this snapshot,
 * so a retry or a mutation made through a public hook cannot switch the decode
 * to a different algorithm or mix a key from another policy into the result.
 *
 * @internal
 */
final class JwtAlgorithmPolicy
{
    private const RSA_KEY_MIN_LENGTH = 2048;

    private const FAMILY_HMAC = 'hmac';
    private const FAMILY_RSA = 'rsa';
    private const FAMILY_EC = 'ec';
    private const FAMILY_EDDSA = 'eddsa';

    private string $algorithm;

    private string $function;

    private string $hashAlgorithm;

    /** @var string|OpenSSLAsymmetricKey|OpenSSLCertificate */
    private $keyMaterial;

    private string $keyFamily;

    private int $keyBits;

    /**
     * @param string|OpenSSLAsymmetricKey|OpenSSLCertificate $keyMaterial
     */
    private function __construct(
        string $algorithm,
        string $function,
        string $hashAlgorithm,
        $keyMaterial,
        string $keyFamily,
        int $keyBits
    ) {
        $this->algorithm = $algorithm;
        $this->function = $function;
        $this->hashAlgorithm = $hashAlgorithm;
        $this->keyMaterial = $keyMaterial;
        $this->keyFamily = $keyFamily;
        $this->keyBits = $keyBits;
    }

    /**
     * @param array<string, string[]> $supportedAlgorithms Snapshot of JWT::$supported_algs
     */
    public static function capture(
        string $algorithm,
        Key $key,
        array $supportedAlgorithms
    ): self {
        return self::captureSnapshot(
            $algorithm,
            $key->getAlgorithm(),
            $key->getKeyMaterial(),
            $supportedAlgorithms
        );
    }

    /**
     * Build the policy from values captured at the start of the transaction.
     *
     * @param string|OpenSSLAsymmetricKey|OpenSSLCertificate $keyMaterial
     * @param array<string, string[]> $supportedAlgorithms Snapshot of JWT::$supported_algs
     */
    public static function captureSnapshot(
        string $algorithm,
        string $keyAlgorithm,
        $keyMaterial,
        array $supportedAlgorithms
    ): self {
        if (empty($supportedAlgorithms[$algorithm])) {
            throw new UnexpectedValueException('Algorithm not supported');
        }

        // Bind the Key's algorithm and material to the header algorithm once.
        // Every later check and the signature verification use this snapshot.
        if (!JWT::constantTimeEquals($keyAlgorithm, $algorithm)) {
            // See issue #351
            throw new UnexpectedValueException('Incorrect key for this algorithm');
        }

        $canonical = self::canonicalAlgorithm($algorithm);
        if (null !== $canonical) {
            list($function, $hashAlgorithm) = $canonical;
        } else {
            list($function, $hashAlgorithm) = $supportedAlgorithms[$algorithm];
        }
        $expectedFamily = self::familyForAlgorithm($algorithm);

        switch ($function) {
            case 'hash_hmac':
                self::assertFunctionFamily($expectedFamily, self::FAMILY_HMAC);
                if (!\is_string($keyMaterial)) {
                    throw new InvalidArgumentException('key must be a string when using hmac');
                }
                $keyBits = self::validateHmacKeyLength($keyMaterial, $hashAlgorithm);
                $family = self::FAMILY_HMAC;
                break;

            case 'openssl':
                if ($algorithm === 'PS256') {
                    self::assertFunctionFamily($expectedFamily, self::FAMILY_RSA);
                    // PS256 has historically delegated key handling to
                    // phpseclib; keep that path and its legacy exceptions.
                    $keyBits = 0;
                    $family = self::FAMILY_RSA;
                    break;
                }
                if (null === $expectedFamily) {
                    // Preserve custom supported_algs entries. Their key type
                    // and length are not inferred from an unknown algorithm
                    // name, but the material is still snapshotted once.
                    $keyMaterial = self::normalizeOpenSslPublicKey($keyMaterial);
                    if (!$keyDetails = \openssl_pkey_get_details($keyMaterial)) {
                        throw new DomainException('Unable to validate key');
                    }
                    $keyBits = (int) $keyDetails['bits'];
                    $family = $function;
                    break;
                }
                if ($expectedFamily !== self::FAMILY_RSA && $expectedFamily !== self::FAMILY_EC) {
                    throw new UnexpectedValueException('Incorrect key for this algorithm');
                }
                $keyMaterial = self::normalizeOpenSslPublicKey($keyMaterial);
                $keyBits = self::validateOpenSslKeyLength($keyMaterial, $algorithm, $expectedFamily);
                $family = $expectedFamily;
                break;

            case 'sodium_crypto':
                self::assertFunctionFamily($expectedFamily, self::FAMILY_EDDSA);
                $family = self::FAMILY_EDDSA;
                $keyBits = 0;
                break;

            default:
                // Preserve the legacy fallback to HMAC for custom entries in
                // supported_algs, but never let it cross algorithm families.
                self::assertFunctionFamily($expectedFamily, self::FAMILY_HMAC);
                if (!\is_string($keyMaterial)) {
                    throw new InvalidArgumentException('key must be a string when using hmac');
                }
                $keyBits = self::validateHmacKeyLength($keyMaterial, $hashAlgorithm);
                $family = self::FAMILY_HMAC;
                break;
        }

        return new self(
            $algorithm,
            $function,
            $hashAlgorithm,
            $keyMaterial,
            $family,
            $keyBits
        );
    }

    public function algorithm(): string
    {
        return $this->algorithm;
    }

    public function function(): string
    {
        return $this->function;
    }

    public function hashAlgorithm(): string
    {
        return $this->hashAlgorithm;
    }

    /**
     * @return string|OpenSSLAsymmetricKey|OpenSSLCertificate
     */
    public function keyMaterial()
    {
        return $this->keyMaterial;
    }

    public function keyFamily(): string
    {
        return $this->keyFamily;
    }

    public function keyBits(): int
    {
        return $this->keyBits;
    }

    public function usesDerSignature(): bool
    {
        return $this->keyFamily === self::FAMILY_EC;
    }

    private static function familyForAlgorithm(string $algorithm): ?string
    {
        if (\str_starts_with($algorithm, 'HS')) {
            return self::FAMILY_HMAC;
        }
        if (\str_starts_with($algorithm, 'RS') || \str_starts_with($algorithm, 'PS')) {
            return self::FAMILY_RSA;
        }
        if (\str_starts_with($algorithm, 'ES')) {
            return self::FAMILY_EC;
        }
        if ($algorithm === 'EdDSA') {
            return self::FAMILY_EDDSA;
        }

        return null;
    }

    /**
     * Standard JOSE algorithms define their cryptographic primitive. The
     * algorithm name in the header is authoritative, so an in-flight change to
     * supported_algs cannot remap it to another hash family.
     *
     * @return null|array{0: string, 1: string}
     */
    private static function canonicalAlgorithm(string $algorithm): ?array
    {
        $algorithms = [
            'HS256' => ['hash_hmac', 'SHA256'],
            'HS384' => ['hash_hmac', 'SHA384'],
            'HS512' => ['hash_hmac', 'SHA512'],
            'RS256' => ['openssl', 'SHA256'],
            'RS384' => ['openssl', 'SHA384'],
            'RS512' => ['openssl', 'SHA512'],
            'PS256' => ['openssl', 'SHA256'],
            'ES256' => ['openssl', 'SHA256'],
            'ES256K' => ['openssl', 'SHA256'],
            'ES384' => ['openssl', 'SHA384'],
            'EdDSA' => ['sodium_crypto', 'EdDSA'],
        ];

        return $algorithms[$algorithm] ?? null;
    }

    private static function assertFunctionFamily(?string $expectedFamily, string $functionFamily): void
    {
        if (null !== $expectedFamily && $expectedFamily !== $functionFamily) {
            throw new UnexpectedValueException('Incorrect key for this algorithm');
        }
    }

    /**
     * @param string|OpenSSLAsymmetricKey|OpenSSLCertificate $keyMaterial
     * @return OpenSSLAsymmetricKey
     */
    private static function normalizeOpenSslPublicKey($keyMaterial): \OpenSSLAsymmetricKey
    {
        $publicKey = \openssl_pkey_get_public($keyMaterial);
        if (!$publicKey) {
            throw new DomainException('OpenSSL unable to validate key');
        }

        return $publicKey;
    }

    private static function validateOpenSslKeyLength(
        \OpenSSLAsymmetricKey $key,
        string $algorithm,
        string $expectedFamily
    ): int {
        if (!$keyDetails = \openssl_pkey_get_details($key)) {
            throw new DomainException('Unable to validate key');
        }

        $keyBits = (int) $keyDetails['bits'];
        if ($expectedFamily === self::FAMILY_RSA) {
            if ($keyBits < self::RSA_KEY_MIN_LENGTH) {
                throw new DomainException('Provided key is too short');
            }
            self::assertOpenSslKeyType($keyDetails, \OPENSSL_KEYTYPE_RSA);
        } else {
            $minKeyLength = (int) \str_replace('ES', '', $algorithm);
            if ($keyBits < $minKeyLength) {
                throw new DomainException('Provided key is too short');
            }
            self::assertOpenSslKeyType($keyDetails, \OPENSSL_KEYTYPE_EC);
        }

        return $keyBits;
    }

    /**
     * @param array<string, mixed> $keyDetails
     */
    private static function assertOpenSslKeyType(array $keyDetails, int $expectedType): void
    {
        if (($keyDetails['type'] ?? null) !== $expectedType) {
            throw new UnexpectedValueException('Incorrect key for this algorithm');
        }
    }

    private static function validateHmacKeyLength(string $key, string $algorithm): int
    {
        $keyLength = \strlen($key) * 8;
        $minKeyLength = (int) \str_replace('SHA', '', $algorithm);
        if ($keyLength < $minKeyLength) {
            throw new DomainException('Provided key is too short');
        }

        return $keyLength;
    }
}
