<?php

namespace Firebase\JWT;

use ArrayAccess;
use InvalidArgumentException;
use LogicException;
use OutOfBoundsException;
use Psr\Cache\CacheItemInterface;
use Psr\Cache\CacheItemPoolInterface;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;
use RuntimeException;
use UnexpectedValueException;

/**
 * @implements ArrayAccess<string, Key>
 */
class CachedKeySet implements ArrayAccess
{
    /**
     * @var string
     */
    private $jwksUri;
    /**
     * @var ClientInterface
     */
    private $httpClient;
    /**
     * @var RequestFactoryInterface
     */
    private $httpFactory;
    /**
     * @var CacheItemPoolInterface
     */
    private $cache;
    /**
     * @var ?int
     */
    private $expiresAfter;
    /**
     * @var ?CacheItemInterface
     */
    private $cacheItem;
    /**
     * @var array<string, array<mixed>>
     */
    private $keySet;
    /**
     * @var string
     */
    private $cacheKey;
    /**
     * @var string
     */
    private $cacheKeyPrefix = 'jwks';
    /**
     * @var int
     */
    private $maxKeyLength = 64;
    /**
     * @var bool
     */
    private $rateLimit;
    /**
     * @var string
     */
    private $rateLimitCacheKey;
    /**
     * @var int
     */
    private $maxCallsPerMinute = 10;
    /**
     * @var string|null
     */
    private $defaultAlg;

    public function __construct(
        string $jwksUri,
        ClientInterface $httpClient,
        RequestFactoryInterface $httpFactory,
        CacheItemPoolInterface $cache,
        ?int $expiresAfter = null,
        bool $rateLimit = false,
        ?string $defaultAlg = null
    ) {
        $this->jwksUri = $jwksUri;
        $this->httpClient = $httpClient;
        $this->httpFactory = $httpFactory;
        $this->cache = $cache;
        $this->expiresAfter = $expiresAfter;
        $this->rateLimit = $rateLimit;
        $this->defaultAlg = $defaultAlg;
        $this->setCacheKeys();
    }

    /**
     * @param string $keyId
     * @return Key
     */
    public function offsetGet($keyId): Key
    {
        if (!$this->keyIdExists($keyId)) {
            throw new OutOfBoundsException('Key ID not found');
        }
        // Re-resolve the key material from the same, consistent key set snapshot
        // that accepted the key id. Never cache a parsed Key across a refresh
        // transaction, otherwise rotation could pair a new "kid" with stale
        // key material.
        return JWK::parseKey($this->keySet[$keyId], $this->defaultAlg);
    }

    /**
     * @param string $keyId
     * @return bool
     */
    public function offsetExists($keyId): bool
    {
        return $this->keyIdExists($keyId);
    }

    /**
     * @param string $offset
     * @param Key $value
     */
    public function offsetSet($offset, $value): void
    {
        throw new LogicException('Method not implemented');
    }

    /**
     * @param string $offset
     */
    public function offsetUnset($offset): void
    {
        throw new LogicException('Method not implemented');
    }

    /**
     * @return array<mixed>
     */
    private function formatJwksForCache(string $jwks): array
    {
        $jwks = json_decode($jwks, true);

        if (!isset($jwks['keys'])) {
            throw new UnexpectedValueException('"keys" member must exist in the JWK Set');
        }

        if (empty($jwks['keys'])) {
            throw new InvalidArgumentException('JWK Set did not contain any keys');
        }

        $keys = [];
        foreach ($jwks['keys'] as $k => $v) {
            // Keys without a "kid" remain addressable by their positional index
            // in the set (previous behavior); keys with a "kid" are addressed
            // by that identifier.
            $kid = (string) (isset($v['kid']) ? $v['kid'] : $k);

            if (isset($keys[$kid])) {
                // Resolving a token must never be ambiguous. Refuse to build a
                // key set in which one "kid" maps to more than one key, because
                // the last entry would otherwise silently shadow the first and
                // could attribute another key's material to the current token.
                throw new UnexpectedValueException(
                    \sprintf(
                        'Conflicting key ID "%s" found in JWK Set; a "kid" must map to exactly one key',
                        $kid
                    )
                );
            }

            $keys[$kid] = $v;
        }

        return $keys;
    }

    private function keyIdExists(string $keyId): bool
    {
        if (null === $this->keySet) {
            $item = $this->getCacheItem();
            // Try to load keys from cache
            if ($item->isHit()) {
                // item found! retrieve it
                $this->keySet = $item->get();
                // If the cached item is a string, the JWKS response was cached (previous behavior).
                // Parse this into expected format array<kid, jwk> instead.
                if (\is_string($this->keySet)) {
                    $this->keySet = $this->formatJwksForCache($this->keySet);
                }
            }
        }

        if (!\is_array($this->keySet) || !isset($this->keySet[$keyId])) {
            if ($this->rateLimitExceeded()) {
                return false;
            }
            $this->refreshKeySet();

            if (!isset($this->keySet[$keyId])) {
                return false;
            }
        }

        return true;
    }

    /**
     * Fetches and installs a fresh JWK Set as a single refresh transaction.
     *
     * The JWKS version, every "kid", its key material and the cached copy are
     * all derived from the same HTTP response: the response is fully fetched and
     * validated into a local, staged key set first, and only then are the
     * in-memory key set and the cache updated atomically. If anything fails
     * (HTTP error, malformed payload, a conflicting "kid", or a cache write
     * failure) neither the in-memory key set nor the cache is modified, so a
     * retry or a "kid" conflict can never attribute another key's material to
     * the current token.
     */
    private function refreshKeySet(): void
    {
        $request = $this->httpFactory->createRequest('GET', $this->jwksUri);
        $jwksResponse = $this->httpClient->sendRequest($request);
        if ($jwksResponse->getStatusCode() !== 200) {
            throw new UnexpectedValueException(
                \sprintf(
                    'HTTP Error: %d %s for URI "%s"',
                    $jwksResponse->getStatusCode(),
                    $jwksResponse->getReasonPhrase(),
                    $this->jwksUri,
                ),
                $jwksResponse->getStatusCode()
            );
        }

        // Stage the complete, validated key set before touching any shared state.
        // A malformed set or a "kid" collision throws here and leaves the
        // previously installed version (and its cache entry) untouched.
        $stagedKeySet = $this->formatJwksForCache((string) $jwksResponse->getBody());

        $item = $this->getCacheItem();
        $item->set($stagedKeySet);
        if ($this->expiresAfter) {
            $item->expiresAfter($this->expiresAfter);
        }

        // Commit the cache first; if this fails, keep serving the previous
        // version instead of diverging the in-memory set from the cache.
        $this->cache->save($item);

        // Commit the in-memory key set last so it always matches the cache.
        $this->keySet = $stagedKeySet;
    }

    private function rateLimitExceeded(): bool
    {
        if (!$this->rateLimit) {
            return false;
        }

        $cacheItem = $this->cache->getItem($this->rateLimitCacheKey);

        $cacheItemData = [];
        if ($cacheItem->isHit() && \is_array($data = $cacheItem->get())) {
            $cacheItemData = $data;
        }

        $callsPerMinute = $cacheItemData['callsPerMinute'] ?? 0;
        $expiry = $cacheItemData['expiry'] ?? new \DateTime('+60 seconds', new \DateTimeZone('UTC'));

        if (++$callsPerMinute > $this->maxCallsPerMinute) {
            return true;
        }

        $cacheItem->set(['expiry' => $expiry, 'callsPerMinute' => $callsPerMinute]);
        $cacheItem->expiresAt($expiry);
        $this->cache->save($cacheItem);
        return false;
    }

    private function getCacheItem(): CacheItemInterface
    {
        if (\is_null($this->cacheItem)) {
            $this->cacheItem = $this->cache->getItem($this->cacheKey);
        }

        return $this->cacheItem;
    }

    private function setCacheKeys(): void
    {
        if (empty($this->jwksUri)) {
            throw new RuntimeException('JWKS URI is empty');
        }

        // ensure we do not have illegal characters
        $key = preg_replace('|[^a-zA-Z0-9_\.!]|', '', $this->jwksUri);

        // add prefix
        $key = $this->cacheKeyPrefix . $key;

        // Hash keys if they exceed $maxKeyLength of 64
        if (\strlen($key) > $this->maxKeyLength) {
            $key = substr(hash('sha256', $key), 0, $this->maxKeyLength);
        }

        $this->cacheKey = $key;

        if ($this->rateLimit) {
            // add prefix
            $rateLimitKey = $this->cacheKeyPrefix . 'ratelimit' . $key;

            // Hash keys if they exceed $maxKeyLength of 64
            if (\strlen($rateLimitKey) > $this->maxKeyLength) {
                $rateLimitKey = substr(hash('sha256', $rateLimitKey), 0, $this->maxKeyLength);
            }

            $this->rateLimitCacheKey = $rateLimitKey;
        }
    }
}
