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
     * @var array<string, array<mixed>>|null
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
     * @var int
     */
    private $maxCallsPerMinute = 10;
    /**
     * @var string|null
     */
    private $defaultAlg;
    /**
     * Tracks whether an HTTP refresh is already in progress for this
     * instance, so concurrent lookups within the same process never trigger
     * more than one JWKS request at a time (single-flight).
     *
     * @var bool
     */
    private $refreshInProgress = false;
    /**
     * Number of HTTP calls recorded in the current rate-limit window. The
     * counters live in the same cache entry as the key set, so their
     * lifecycles cannot drift apart.
     *
     * @var int
     */
    private $rateLimitCalls = 0;
    /**
     * End of the current rate-limit window. Null until lazily initialized.
     *
     * @var \DateTimeInterface|null
     */
    private $rateLimitExpiry;

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
            $kid = isset($v['kid']) ? $v['kid'] : $k;
            $keys[(string) $kid] = $v;
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
                $cachedKeySet = $this->extractKeySetFromCacheValue($item->get());
                if (null !== $cachedKeySet) {
                    $this->keySet = $cachedKeySet;
                }
            }
        }

        if (!isset($this->keySet[$keyId])) {
            // A refresh is already running for this instance (concurrent
            // lookup): never fire another HTTP request. The existing keys
            // remain available and a missing kid simply does not resolve.
            if ($this->refreshInProgress || $this->rateLimitExceeded()) {
                return false;
            }

            // refreshKeySet() only returns false when rate limiting swallowed
            // an HTTP failure. The previously cached/in-memory keys are kept
            // untouched, so lookups of still-valid kids keep working and a
            // missing kid fails instead of silently succeeding with a stale key.
            if (!$this->refreshKeySet() || !isset($this->keySet[$keyId])) {
                return false;
            }
        }

        return true;
    }

    /**
     * Fetches the JWKS over HTTP and refreshes the in-memory key set and the
     * cache. The healthy cache entry is only ever overwritten when a refresh
     * succeeds; rate limiting and refresh failures preserve the existing keys
     * instead of clearing them.
     *
     * @return bool true when the key set was refreshed successfully
     */
    private function refreshKeySet(): bool
    {
        $this->refreshInProgress = true;

        try {
            $request = $this->httpFactory->createRequest('GET', $this->jwksUri);
            $jwksResponse = $this->httpClient->sendRequest($request);

            if ($jwksResponse->getStatusCode() !== 200) {
                $exception = new UnexpectedValueException(
                    \sprintf(
                        'HTTP Error: %d %s for URI "%s"',
                        $jwksResponse->getStatusCode(),
                        $jwksResponse->getReasonPhrase(),
                        $this->jwksUri,
                    ),
                    $jwksResponse->getStatusCode()
                );

                // With rate limiting enabled, count the failed call (e.g. a
                // 429) against the limit and keep serving the cached keys
                // instead of clearing them or throwing. Without rate
                // limiting, the HTTP error is propagated as before.
                if ($this->rateLimit) {
                    $this->recordRateLimitCall();

                    return false;
                }

                throw $exception;
            }

            $this->keySet = $this->formatJwksForCache((string) $jwksResponse->getBody());

            // Count every actual HTTP call, successful or not, so retries
            // after a refresh failure cannot turn into unlimited requests.
            // The counters and the refreshed key set are then persisted
            // together in a single write below.
            if ($this->rateLimit) {
                $this->initializeRateLimitState();
                $this->rolloverRateLimitWindowIfElapsed();
                $this->rateLimitCalls++;
            }

            $item = $this->getCacheItem();
            $item->set($this->buildCacheValue($this->keySet));
            $this->applyKeySetTtl($item);
            $this->cache->save($item);

            return true;
        } finally {
            $this->refreshInProgress = false;
        }
    }

    private function rateLimitExceeded(): bool
    {
        if (!$this->rateLimit) {
            return false;
        }

        $this->initializeRateLimitState();
        $this->rolloverRateLimitWindowIfElapsed();

        return $this->rateLimitCalls >= $this->maxCallsPerMinute;
    }

    /**
     * Records an actual HTTP call (including failed ones such as a 429)
     * against the rate limit, keeping the rate-limit state and the key set in
     * the same cache entry and preventing refresh retries from looping into
     * endless requests.
     */
    private function recordRateLimitCall(): void
    {
        if (!$this->rateLimit) {
            return;
        }

        $this->initializeRateLimitState();
        $this->rolloverRateLimitWindowIfElapsed();
        $this->rateLimitCalls++;
        $this->persistRateLimitState();
    }

    /**
     * Starts a fresh rate-limit window once the current one has elapsed, so
     * the limit applies "per minute" instead of blocking the instance forever
     * after the first window fills up.
     */
    private function rolloverRateLimitWindowIfElapsed(): void
    {
        if (null === $this->rateLimitExpiry) {
            return;
        }

        $now = (new \DateTime('now', new \DateTimeZone('UTC')))->getTimestamp();
        if ($this->rateLimitExpiry->getTimestamp() <= $now) {
            $this->rateLimitExpiry = new \DateTime('+60 seconds', new \DateTimeZone('UTC'));
            $this->rateLimitCalls = 0;
        }
    }

    /**
     * Persists the current rate-limit counters together with the healthy key
     * set in the single cache entry that governs both lifecycles. A refresh
     * failure never removes or replaces the cached key set.
     */
    private function persistRateLimitState(): void
    {
        $item = $this->getCacheItem();
        if (null === $this->keySet) {
            // No healthy key set exists yet (e.g. the very first fetch was a
            // 429). Persist the counters on their own rather than caching an
            // empty key set, which would otherwise shadow a later success.
            $item->set(['rateLimit' => $this->buildRateLimitData()]);
            // A counter-only entry is bound to the rate-limit window.
            $item->expiresAt($this->rateLimitExpiry);
        } else {
            $item->set($this->buildCacheValue($this->keySet));
            // Keep the healthy key set's own TTL; a rate-limit update must not
            // shorten (or clear) the lifetime of a healthy cache entry.
            $this->applyKeySetTtl($item);
        }
        $this->cache->save($item);
    }

    /**
     * Applies the configured key-set TTL to a cache item. When no TTL is
     * configured the entry is stored without an expiration, matching the
     * previous key-set caching behavior.
     */
    private function applyKeySetTtl(CacheItemInterface $item): void
    {
        if ($this->expiresAfter) {
            $item->expiresAfter($this->expiresAfter);
        } else {
            $item->expiresAt(null);
        }
    }

    /**
     * Wraps the key set and the rate-limit state into the single cache entry
     * shared by both lifecycles.
     *
     * @param array<string, array<mixed>> $keySet
     * @return array<string, mixed>
     */
    private function buildCacheValue(array $keySet): array
    {
        return [
            'keys' => $keySet,
            'rateLimit' => $this->buildRateLimitData(),
        ];
    }

    /**
     * @return array<string, \DateTimeInterface|int>
     */
    private function buildRateLimitData(): array
    {
        return [
            'expiry' => $this->rateLimitExpiry,
            'callsPerMinute' => $this->rateLimitCalls,
        ];
    }

    /**
     * Reads the key set out of a cached value. Supports the unified wrapper
     * format as well as the two previous cache formats: a plain array of
     * `<kid, jwk>` entries and a raw JWKS response string.
     *
     * @param mixed $cachedValue
     * @return array<string, array<mixed>>|null
     */
    private function extractKeySetFromCacheValue($cachedValue): ?array
    {
        if (\is_string($cachedValue)) {
            // The JWKS response was cached as a string (previous behavior).
            // Parse this into expected format array<kid, jwk> instead.
            return $this->formatJwksForCache($cachedValue);
        }

        if (!\is_array($cachedValue)) {
            throw new UnexpectedValueException('Invalid cached JWKS value');
        }

        // Unified wrapper format: the rate-limit state shares the entry with
        // the key set, so both are refreshed on the same lifecycle. A wrapper
        // without keys only carries rate-limit counters.
        if (\array_key_exists('rateLimit', $cachedValue)) {
            if (isset($cachedValue['rateLimit']) && \is_array($cachedValue['rateLimit'])) {
                $this->hydrateRateLimitState($cachedValue['rateLimit']);
            }

            return \is_array($cachedValue['keys'] ?? null) ? $cachedValue['keys'] : null;
        }

        // Previous behavior: the cache entry was the key set itself.
        return $cachedValue;
    }

    /**
     * Restores the in-memory rate-limit counters from a cached wrapper entry.
     * A missing or elapsed window starts a fresh one.
     *
     * @param array<string, mixed> $rateLimitData
     */
    private function hydrateRateLimitState(array $rateLimitData): void
    {
        $expiry = $rateLimitData['expiry'] ?? null;

        if ($expiry instanceof \DateTimeInterface
            && $expiry->getTimestamp() > (new \DateTime('now', new \DateTimeZone('UTC')))->getTimestamp()
        ) {
            $this->rateLimitExpiry = $expiry;
            $this->rateLimitCalls = (int) ($rateLimitData['callsPerMinute'] ?? 0);
        }
    }

    private function getCacheItem(): CacheItemInterface
    {
        if (\is_null($this->cacheItem)) {
            $this->cacheItem = $this->cache->getItem($this->cacheKey);
        }

        return $this->cacheItem;
    }

    /**
     * Initializes the rate-limit window for this instance and hydrates the
     * counters from the shared cache entry when a non-elapsed window exists.
     */
    private function initializeRateLimitState(): void
    {
        if (null !== $this->rateLimitExpiry) {
            return;
        }

        $this->rateLimitExpiry = new \DateTime('+60 seconds', new \DateTimeZone('UTC'));
        $this->rateLimitCalls = 0;

        $item = $this->cache->getItem($this->cacheKey);
        if ($item->isHit() && \is_array($data = $item->get())
            && isset($data['rateLimit']) && \is_array($data['rateLimit'])
        ) {
            $this->hydrateRateLimitState($data['rateLimit']);
        }
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
    }
}
