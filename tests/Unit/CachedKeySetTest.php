<?php

namespace Firebase\JWT;

use LogicException;
use OutOfBoundsException;
use PHPUnit\Framework\TestCase;
use Prophecy\Argument;
use Prophecy\PhpUnit\ProphecyTrait;
use Psr\Cache\CacheItemInterface;
use Psr\Cache\CacheItemPoolInterface;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;
use RuntimeException;

class CachedKeySetTest extends TestCase
{
    use ProphecyTrait;

    private $testJwksUri = 'https://jwk.uri';
    private $testJwksUriKey = 'jwkshttpsjwk.uri';
    private $testJwks1 = '{"keys": [{"kid":"foo","kty":"RSA","alg":"foo","n":"","e":""}]}';
    private $testCachedJwks1 = ['foo' => ['kid' => 'foo', 'kty' => 'RSA', 'alg' => 'foo', 'n' => '', 'e' => '']];
    private $testJwks2 = '{"keys": [{"kid":"bar","kty":"RSA","alg":"bar","n":"","e":""}]}';
    private $testJwks3 = '{"keys": [{"kid":"baz","kty":"RSA","n":"","e":""}]}';

    private $googleRsaUri = 'https://www.googleapis.com/oauth2/v3/certs';
    private $googleEcUri = 'https://www.gstatic.com/iap/verify/public_key-jwk';

    public function testEmptyUriThrowsException()
    {
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('JWKS URI is empty');

        $cachedKeySet = new CachedKeySet(
            '',
            $this->prophesize(ClientInterface::class)->reveal(),
            $this->prophesize(RequestFactoryInterface::class)->reveal(),
            $this->prophesize(CacheItemPoolInterface::class)->reveal()
        );

        $cachedKeySet['foo'];
    }

    public function testOffsetSetThrowsException()
    {
        $this->expectException(LogicException::class);
        $this->expectExceptionMessage('Method not implemented');

        $cachedKeySet = new CachedKeySet(
            $this->testJwksUri,
            $this->prophesize(ClientInterface::class)->reveal(),
            $this->prophesize(RequestFactoryInterface::class)->reveal(),
            $this->prophesize(CacheItemPoolInterface::class)->reveal()
        );

        $cachedKeySet['foo'] = 'bar';
    }

    public function testOffsetUnsetThrowsException()
    {
        $this->expectException(LogicException::class);
        $this->expectExceptionMessage('Method not implemented');

        $cachedKeySet = new CachedKeySet(
            $this->testJwksUri,
            $this->prophesize(ClientInterface::class)->reveal(),
            $this->prophesize(RequestFactoryInterface::class)->reveal(),
            $this->prophesize(CacheItemPoolInterface::class)->reveal()
        );

        unset($cachedKeySet['foo']);
    }

    public function testOutOfBoundsThrowsException()
    {
        $this->expectException(OutOfBoundsException::class);
        $this->expectExceptionMessage('Key ID not found');

        $cachedKeySet = new CachedKeySet(
            $this->testJwksUri,
            $this->getMockHttpClient($this->testJwks1),
            $this->getMockHttpFactory(),
            $this->getMockEmptyCache()
        );

        // keyID doesn't exist
        $cachedKeySet['bar'];
    }

    public function testInvalidHttpResponseThrowsException()
    {
        $this->expectException(\UnexpectedValueException::class);
        $this->expectExceptionMessage('HTTP Error: 404 URL not found');
        $this->expectExceptionCode(404);

        $response = $this->prophesize('Psr\Http\Message\ResponseInterface');
        $response->getStatusCode()
            ->shouldBeCalled()
            ->willReturn(404);
        $response->getReasonPhrase()
            ->shouldBeCalledTimes(1)
            ->willReturn('URL not found');

        $http = $this->prophesize(ClientInterface::class);
        $http->sendRequest(Argument::any())
            ->shouldBeCalledTimes(1)
            ->willReturn($response->reveal());

        $cachedKeySet = new CachedKeySet(
            $this->testJwksUri,
            $http->reveal(),
            $this->getMockHttpFactory(),
            $this->getMockEmptyCache()
        );

        isset($cachedKeySet[0]);
    }

    public function testWithExistingKeyId()
    {
        $cachedKeySet = new CachedKeySet(
            $this->testJwksUri,
            $this->getMockHttpClient($this->testJwks1),
            $this->getMockHttpFactory(),
            $this->getMockEmptyCache()
        );
        $this->assertInstanceOf(Key::class, $cachedKeySet['foo']);
        $this->assertSame('foo', $cachedKeySet['foo']->getAlgorithm());
    }

    public function testWithDefaultAlg()
    {
        $cachedKeySet = new CachedKeySet(
            $this->testJwksUri,
            $this->getMockHttpClient($this->testJwks3),
            $this->getMockHttpFactory(),
            $this->getMockEmptyCache(),
            null,
            false,
            'baz256'
        );
        $this->assertInstanceOf(Key::class, $cachedKeySet['baz']);
        $this->assertSame('baz256', $cachedKeySet['baz']->getAlgorithm());
    }

    public function testKeyIdIsCached()
    {
        $cacheItem = $this->prophesize(CacheItemInterface::class);
        $cacheItem->isHit()
            ->willReturn(true);
        $cacheItem->get()
            ->willReturn($this->testCachedJwks1);

        $cache = $this->prophesize(CacheItemPoolInterface::class);
        $cache->getItem($this->testJwksUriKey)
            ->willReturn($cacheItem->reveal());
        $cache->save(Argument::any())
            ->willReturn(true);

        $cachedKeySet = new CachedKeySet(
            $this->testJwksUri,
            $this->prophesize(ClientInterface::class)->reveal(),
            $this->prophesize(RequestFactoryInterface::class)->reveal(),
            $cache->reveal()
        );
        $this->assertInstanceOf(Key::class, $cachedKeySet['foo']);
        $this->assertSame('foo', $cachedKeySet['foo']->getAlgorithm());
    }

    public function testCachedKeyIdRefresh()
    {
        $cacheItem = $this->prophesize(CacheItemInterface::class);
        $cacheItem->isHit()
            ->shouldBeCalledOnce()
            ->willReturn(true);
        $cacheItem->get()
            ->shouldBeCalledOnce()
            ->willReturn($this->testCachedJwks1);
        $cacheItem->set(Argument::any())
            ->shouldBeCalledOnce()
            ->will(function () {
                return $this;
            });

        $cache = $this->prophesize(CacheItemPoolInterface::class);
        $cache->getItem($this->testJwksUriKey)
            ->shouldBeCalledOnce()
            ->willReturn($cacheItem->reveal());
        $cache->save(Argument::any())
            ->shouldBeCalledOnce()
            ->willReturn(true);

        $cachedKeySet = new CachedKeySet(
            $this->testJwksUri,
            $this->getMockHttpClient($this->testJwks2), // updated JWK
            $this->getMockHttpFactory(),
            $cache->reveal()
        );
        $this->assertInstanceOf(Key::class, $cachedKeySet['foo']);
        $this->assertSame('foo', $cachedKeySet['foo']->getAlgorithm());

        $this->assertInstanceOf(Key::class, $cachedKeySet['bar']);
        $this->assertSame('bar', $cachedKeySet['bar']->getAlgorithm());
    }

    public function testKeyIdIsCachedFromPreviousFormat()
    {
        $cacheItem = $this->prophesize(CacheItemInterface::class);
        $cacheItem->isHit()
            ->willReturn(true);
        $cacheItem->get()
            ->willReturn($this->testJwks1);

        $cache = $this->prophesize(CacheItemPoolInterface::class);
        $cache->getItem($this->testJwksUriKey)
            ->willReturn($cacheItem->reveal());
        $cache->save(Argument::any())
            ->willReturn(true);

        $cachedKeySet = new CachedKeySet(
            $this->testJwksUri,
            $this->prophesize(ClientInterface::class)->reveal(),
            $this->prophesize(RequestFactoryInterface::class)->reveal(),
            $cache->reveal()
        );
        $this->assertInstanceOf(Key::class, $cachedKeySet['foo']);
        $this->assertSame('foo', $cachedKeySet['foo']->getAlgorithm());
    }

    public function testCachedKeyIdRefreshFromPreviousFormat()
    {
        $cacheItem = $this->prophesize(CacheItemInterface::class);
        $cacheItem->isHit()
            ->shouldBeCalledOnce()
            ->willReturn(true);
        $cacheItem->get()
            ->shouldBeCalledOnce()
            ->willReturn($this->testJwks1);
        $cacheItem->set(Argument::any())
            ->shouldBeCalledOnce()
            ->will(function () {
                return $this;
            });

        $cache = $this->prophesize(CacheItemPoolInterface::class);
        $cache->getItem($this->testJwksUriKey)
            ->shouldBeCalledOnce()
            ->willReturn($cacheItem->reveal());
        $cache->save(Argument::any())
            ->shouldBeCalledOnce()
            ->willReturn(true);

        $cachedKeySet = new CachedKeySet(
            $this->testJwksUri,
            $this->getMockHttpClient($this->testJwks2), // updated JWK
            $this->getMockHttpFactory(),
            $cache->reveal()
        );
        $this->assertInstanceOf(Key::class, $cachedKeySet['foo']);
        $this->assertSame('foo', $cachedKeySet['foo']->getAlgorithm());

        $this->assertInstanceOf(Key::class, $cachedKeySet['bar']);
        $this->assertSame('bar', $cachedKeySet['bar']->getAlgorithm());
    }

    public function testCacheItemWithExpiresAfter()
    {
        $expiresAfter = 10;
        $cacheItem = $this->prophesize(CacheItemInterface::class);
        $cacheItem->isHit()
            ->shouldBeCalledOnce()
            ->willReturn(false);
        $cacheItem->set(Argument::any())
            ->shouldBeCalledOnce()
            ->will(function () {
                return $this;
            });
        $cacheItem->expiresAfter($expiresAfter)
            ->shouldBeCalledOnce()
            ->will(function () {
                return $this;
            });

        $cache = $this->prophesize(CacheItemPoolInterface::class);
        $cache->getItem($this->testJwksUriKey)
            ->shouldBeCalledOnce()
            ->willReturn($cacheItem->reveal());
        $cache->save(Argument::any())
            ->shouldBeCalledOnce();

        $cachedKeySet = new CachedKeySet(
            $this->testJwksUri,
            $this->getMockHttpClient($this->testJwks1),
            $this->getMockHttpFactory(),
            $cache->reveal(),
            $expiresAfter
        );
        $this->assertInstanceOf(Key::class, $cachedKeySet['foo']);
        $this->assertSame('foo', $cachedKeySet['foo']->getAlgorithm());
    }

    public function testJwtVerify()
    {
        $privKey1 = file_get_contents(__DIR__ . '/data/rsa1-private.pem');
        $payload = ['sub' => 'foo', 'exp' => strtotime('+10 seconds')];
        $msg = JWT::encode($payload, $privKey1, 'RS256', 'jwk1');

        // format the cached value to match the expected format
        $cachedJwks = [];
        $rsaKeySet = file_get_contents(__DIR__ . '/data/rsa-jwkset.json');
        foreach (json_decode($rsaKeySet, true)['keys'] as $k => $v) {
            $cachedJwks[$v['kid']] = $v;
        }

        $cacheItem = $this->prophesize(CacheItemInterface::class);
        $cacheItem->isHit()
            ->willReturn(true);
        $cacheItem->get()
            ->willReturn($cachedJwks);

        $cache = $this->prophesize(CacheItemPoolInterface::class);
        $cache->getItem($this->testJwksUriKey)
            ->willReturn($cacheItem->reveal());

        $cachedKeySet = new CachedKeySet(
            $this->testJwksUri,
            $this->prophesize(ClientInterface::class)->reveal(),
            $this->prophesize(RequestFactoryInterface::class)->reveal(),
            $cache->reveal()
        );

        $result = JWT::decode($msg, $cachedKeySet);

        $this->assertSame('foo', $result->sub);
    }

    public function testRateLimit()
    {
        // We request the key 11 times, HTTP should only be called 10 times
        $shouldBeCalledTimes = 10;

        // Instantiate the cached key set
        $cachedKeySet = new CachedKeySet(
            $this->testJwksUri,
            $this->getMockHttpClient($this->testJwks1, $shouldBeCalledTimes),
            $this->getMockHttpFactory($shouldBeCalledTimes),
            $this->getTestMemoryCacheItemPool(),
            10,  // expires after seconds
            true // enable rate limiting
        );

        $invalidKid = 'invalidkey';
        for ($i = 0; $i < 10; $i++) {
            $this->assertFalse(isset($cachedKeySet[$invalidKid]));
        }
        // The 11th time does not call HTTP
        $this->assertFalse(isset($cachedKeySet[$invalidKid]));
    }

    public function testRateLimitWithExpiresAfter()
    {
        // We request the key 17 times, HTTP should only be called 15 times
        $shouldBeCalledTimes = 10;
        $cachedTimes = 2;
        $afterExpirationTimes = 5;

        $totalHttpTimes = $shouldBeCalledTimes + $afterExpirationTimes;

        $cachePool = $this->getTestMemoryCacheItemPool();

        // Instantiate the cached key set
        $cachedKeySet = new CachedKeySet(
            $this->testJwksUri,
            $this->getMockHttpClient($this->testJwks1, $totalHttpTimes),
            $this->getMockHttpFactory($totalHttpTimes),
            $cachePool,
            10,   // expires after seconds
            true // enable rate limiting
        );

        $invalidKid = 'invalidkey';
        for ($i = 0; $i < $shouldBeCalledTimes; $i++) {
            $this->assertFalse(isset($cachedKeySet[$invalidKid]));
        }

        // The next calls do not call HTTP
        for ($i = 0; $i < $cachedTimes; $i++) {
            $this->assertFalse(isset($cachedKeySet[$invalidKid]));
        }

        // The rate-limit state lives in the same cache entry as the key set.
        // Elapse the rate-limit window so requests are allowed again (a fresh
        // window starts with a zeroed counter).
        $expiryProperty = new \ReflectionProperty(CachedKeySet::class, 'rateLimitExpiry');
        $expiryProperty->setAccessible(true);
        $expiryProperty->setValue(
            $cachedKeySet,
            new \DateTime('-1 second', new \DateTimeZone('UTC'))
        );

        // These calls DO call HTTP because the rate-limit window elapsed
        for ($i = 0; $i < $afterExpirationTimes; $i++) {
            $this->assertFalse(isset($cachedKeySet[$invalidKid]));
        }
    }

    public function testRateLimitAndKeySetShareOneCacheEntry()
    {
        $cachePool = $this->getTestMemoryCacheItemPool();

        $cachedKeySet = new CachedKeySet(
            $this->testJwksUri,
            $this->getMockHttpClient($this->testJwks1, 1),
            $this->getMockHttpFactory(1),
            $cachePool,
            null,
            true // enable rate limiting
        );

        // A successful refresh stores the key set and the rate-limit counters
        // together in a single cache entry.
        $this->assertTrue(isset($cachedKeySet['foo']));

        $item = $cachePool->getItem($this->testJwksUriKey);
        $this->assertTrue($item->isHit());
        $data = $item->get();
        $this->assertIsArray($data);
        $this->assertArrayHasKey('keys', $data);
        $this->assertArrayHasKey('rateLimit', $data);
        $this->assertArrayHasKey('foo', $data['keys']);
        $this->assertSame(1, $data['rateLimit']['callsPerMinute']);
        $this->assertInstanceOf(\DateTimeInterface::class, $data['rateLimit']['expiry']);

        // The legacy standalone rate-limit key must no longer be used.
        $this->assertFalse($cachePool->hasItem('jwksratelimitjwkshttpsjwk.uri'));
    }

    public function testRateLimitRetriesDoNotMakeUnlimitedRequestsOnHttpError()
    {
        $response = $this->prophesize('Psr\Http\Message\ResponseInterface');
        $response->getStatusCode()
            ->shouldBeCalledTimes(10)
            ->willReturn(429);
        $response->getReasonPhrase()
            ->willReturn('Too Many Requests');

        $http = $this->prophesize(ClientInterface::class);
        $http->sendRequest(Argument::any())
            ->shouldBeCalledTimes(10)
            ->willReturn($response->reveal());

        $cachedKeySet = new CachedKeySet(
            $this->testJwksUri,
            $http->reveal(),
            $this->getMockHttpFactory(10),
            $this->getTestMemoryCacheItemPool(),
            null,
            true // enable rate limiting
        );

        // Even with far more attempts than the limit, HTTP is called at most
        // the configured number of times and no exception escapes.
        for ($i = 0; $i < 25; $i++) {
            $this->assertFalse(isset($cachedKeySet['missing']));
        }
    }

    public function testRefreshFailureKeepsHealthyCachedKeys()
    {
        // First call succeeds and caches a healthy key set.
        $successResponse = $this->prophesize('Psr\Http\Message\ResponseInterface');
        $successResponse->getStatusCode()->willReturn(200);
        $body = $this->prophesize('Psr\Http\Message\StreamInterface');
        $body->__toString()->willReturn($this->testJwks1);
        $successResponse->getBody()->willReturn($body->reveal());

        // All subsequent refreshes are rate limited by the JWKS endpoint.
        $errorResponse = $this->prophesize('Psr\Http\Message\ResponseInterface');
        $errorResponse->getStatusCode()->willReturn(429);
        $errorResponse->getReasonPhrase()->willReturn('Too Many Requests');

        $http = $this->prophesize(ClientInterface::class);
        $http->sendRequest(Argument::any())
            ->willReturn($successResponse->reveal(), $errorResponse->reveal());

        $cachePool = $this->getTestMemoryCacheItemPool();
        $cachedKeySet = new CachedKeySet(
            $this->testJwksUri,
            $http->reveal(),
            $this->getMockHttpFactory(2),
            $cachePool,
            null,
            true
        );

        // The healthy key is available from the initial fetch.
        $this->assertTrue(isset($cachedKeySet['foo']));

        // A rotated kid triggers a refresh, which fails with 429.
        $this->assertFalse(isset($cachedKeySet['rotated']));

        // The healthy cached key set is untouched: the old, still-valid key
        // keeps resolving instead of the cache being cleared.
        $this->assertTrue(isset($cachedKeySet['foo']));
        $this->assertInstanceOf(Key::class, $cachedKeySet['foo']);

        // A brand new instance reading the same cache entry still sees the
        // healthy keys, proving the cache entry was not cleared on failure.
        $newCachedKeySet = new CachedKeySet(
            $this->testJwksUri,
            $this->prophesize(ClientInterface::class)->reveal(),
            $this->prophesize(RequestFactoryInterface::class)->reveal(),
            $cachePool,
            null,
            true
        );
        $this->assertTrue(isset($newCachedKeySet['foo']));
    }

    public function testHttpErrorWithoutRateLimitStillThrows()
    {
        $response = $this->prophesize('Psr\Http\Message\ResponseInterface');
        $response->getStatusCode()
            ->shouldBeCalledOnce()
            ->willReturn(429);
        $response->getReasonPhrase()
            ->shouldBeCalledOnce()
            ->willReturn('Too Many Requests');

        $http = $this->prophesize(ClientInterface::class);
        $http->sendRequest(Argument::any())
            ->shouldBeCalledOnce()
            ->willReturn($response->reveal());

        $cachedKeySet = new CachedKeySet(
            $this->testJwksUri,
            $http->reveal(),
            $this->getMockHttpFactory(1),
            $this->getMockEmptyCache()
        );

        $this->expectException(\UnexpectedValueException::class);
        $this->expectExceptionMessage('HTTP Error: 429 Too Many Requests');
        $this->expectExceptionCode(429);

        isset($cachedKeySet['foo']);
    }

    public function testConcurrentLookupsTriggerSingleHttpRequest()
    {
        // The HTTP mock fails the test if it is ever called: when a refresh is
        // already in progress, concurrent lookups must short-circuit.
        $http = $this->prophesize(ClientInterface::class);
        $http->sendRequest(Argument::any())
            ->shouldNotBeCalled();

        $cachedKeySet = new CachedKeySet(
            $this->testJwksUri,
            $http->reveal(),
            $this->prophesize(RequestFactoryInterface::class)->reveal(),
            $this->getTestMemoryCacheItemPool(),
            null,
            true
        );

        // Simulate an in-flight refresh (e.g. another concurrent decode).
        $reflection = new \ReflectionProperty(CachedKeySet::class, 'refreshInProgress');
        $reflection->setAccessible(true);
        $reflection->setValue($cachedKeySet, true);

        $this->assertFalse(isset($cachedKeySet['other']));
    }

    public function testRateLimitWindowRolloversAfterExpiry()
    {
        // All responses are valid; once the minute window elapses, calls must
        // be allowed again instead of being rate limited forever.
        $cachedKeySet = new CachedKeySet(
            $this->testJwksUri,
            $this->getMockHttpClient($this->testJwks1, 11),
            $this->getMockHttpFactory(11),
            $this->getTestMemoryCacheItemPool(),
            10,
            true
        );

        $invalidKid = 'invalidkey';
        for ($i = 0; $i < 10; $i++) {
            $this->assertFalse(isset($cachedKeySet[$invalidKid]));
        }
        // The window is full: the next lookup does not call HTTP.
        $this->assertFalse(isset($cachedKeySet[$invalidKid]));

        // Force the current window into the past.
        $expiryProperty = new \ReflectionProperty(CachedKeySet::class, 'rateLimitExpiry');
        $expiryProperty->setAccessible(true);
        $expiryProperty->setValue(
            $cachedKeySet,
            new \DateTime('-1 second', new \DateTimeZone('UTC'))
        );

        // A fresh window allows HTTP calls again.
        $this->assertFalse(isset($cachedKeySet[$invalidKid]));
    }

    public function testFirstFetchHttpErrorRecoversAfterWindowRollover()
    {
        $errorResponse = $this->prophesize('Psr\Http\Message\ResponseInterface');
        $errorResponse->getStatusCode()->willReturn(429);
        $errorResponse->getReasonPhrase()->willReturn('Too Many Requests');

        $successBody = $this->prophesize('Psr\Http\Message\StreamInterface');
        $successBody->__toString()->willReturn($this->testJwks1);
        $successResponse = $this->prophesize('Psr\Http\Message\ResponseInterface');
        $successResponse->getStatusCode()->willReturn(200);
        $successResponse->getBody()->willReturn($successBody->reveal());

        $http = $this->prophesize(ClientInterface::class);
        $http->sendRequest(Argument::any())
            ->willReturn($errorResponse->reveal(), $successResponse->reveal());

        $cachedKeySet = new CachedKeySet(
            $this->testJwksUri,
            $http->reveal(),
            $this->getMockHttpFactory(2),
            $this->getTestMemoryCacheItemPool(),
            null,
            true
        );

        // The very first fetch is rate limited: no keys, no exception.
        $this->assertFalse(isset($cachedKeySet['foo']));

        // Expire the window so the lookup is allowed to retry.
        $expiryProperty = new \ReflectionProperty(CachedKeySet::class, 'rateLimitExpiry');
        $expiryProperty->setAccessible(true);
        $expiryProperty->setValue(
            $cachedKeySet,
            new \DateTime('-1 second', new \DateTimeZone('UTC'))
        );

        // The retry succeeds and the key resolves.
        $this->assertTrue(isset($cachedKeySet['foo']));
        $this->assertSame('foo', $cachedKeySet['foo']->getAlgorithm());
    }

    /**
     * @dataProvider provideFullIntegration
     */
    public function testFullIntegration(string $jwkUri): void
    {
        if (!class_exists(\GuzzleHttp\Psr7\HttpFactory::class)) {
            self::markTestSkipped('Guzzle 7 only');
        }
        // Create cache and http objects
        $cache = $this->getTestMemoryCacheItemPool();
        $http = new \GuzzleHttp\Client();
        $factory = new \GuzzleHttp\Psr7\HttpFactory();

        // Determine "kid" dynamically, because these constantly change
        $response = $http->get($jwkUri);
        $json = (string) $response->getBody();
        $keys = json_decode($json, true);
        $kid = $keys['keys'][0]['kid'] ?? null;
        $this->assertNotNull($kid);

        // Instantiate the cached key set
        $cachedKeySet = new CachedKeySet(
            $jwkUri,
            $http,
            $factory,
            $cache
        );

        $this->assertArrayHasKey($kid, $cachedKeySet);
        $key = $cachedKeySet[$kid];
        $this->assertInstanceOf(Key::class, $key);
        $this->assertSame($keys['keys'][0]['alg'], $key->getAlgorithm());
    }

    public function provideFullIntegration()
    {
        return [
            [$this->googleRsaUri],
            [$this->googleEcUri, 'LYyP2g']
        ];
    }

    private function getMockHttpClient($testJwks, int $timesCalled = 1)
    {
        $body = $this->prophesize('Psr\Http\Message\StreamInterface');
        $body->__toString()
            ->shouldBeCalledTimes($timesCalled)
            ->willReturn($testJwks);

        $response = $this->prophesize('Psr\Http\Message\ResponseInterface');
        $response->getBody()
            ->shouldBeCalledTimes($timesCalled)
            ->willReturn($body->reveal());
        $response->getStatusCode()
            ->shouldBeCalledTimes($timesCalled)
            ->willReturn(200);

        $http = $this->prophesize(ClientInterface::class);
        $http->sendRequest(Argument::any())
            ->shouldBeCalledTimes($timesCalled)
            ->willReturn($response->reveal());

        return $http->reveal();
    }

    private function getMockHttpFactory(int $timesCalled = 1)
    {
        $request = $this->prophesize('Psr\Http\Message\RequestInterface');
        $factory = $this->prophesize(RequestFactoryInterface::class);
        $factory->createRequest('GET', $this->testJwksUri)
            ->shouldBeCalledTimes($timesCalled)
            ->willReturn($request->reveal());

        return $factory->reveal();
    }

    private function getMockEmptyCache()
    {
        $cacheItem = $this->prophesize(CacheItemInterface::class);
        $cacheItem->isHit()
            ->shouldBeCalledOnce()
            ->willReturn(false);
        $cacheItem->set(Argument::any())
            ->will(function () {
                return $this;
            });

        $cache = $this->prophesize(CacheItemPoolInterface::class);
        $cache->getItem($this->testJwksUriKey)
            ->shouldBeCalledOnce()
            ->willReturn($cacheItem->reveal());
        $cache->save(Argument::any())
            ->willReturn(true);

        return $cache->reveal();
    }

    private function getTestMemoryCacheItemPool()
    {
        return new class() implements CacheItemPoolInterface {
            private $items;
            private $deferredItems;

            public function getItem($key): CacheItemInterface
            {
                $item = current($this->getItems([$key]));
                $item->expiresAt(null); // mimic symfony cache behavior

                return $item;
            }

            public function getItems(array $keys = []): iterable
            {
                $items = [];

                foreach ($keys as $key) {
                    $items[$key] = $this->hasItem($key) ?
                        clone $this->items[$key] :
                        $this->getTestMemoryCacheItem($key);
                }

                return $items;
            }

            public function hasItem($key): bool
            {
                return isset($this->items[$key]) && $this->items[$key]->isHit();
            }

            public function clear(): bool
            {
                $this->items = [];
                $this->deferredItems = [];

                return true;
            }

            public function deleteItem($key): bool
            {
                return $this->deleteItems([$key]);
            }

            public function deleteItems(array $keys): bool
            {
                foreach ($keys as $key) {
                    unset($this->items[$key]);
                }

                return true;
            }

            public function save(CacheItemInterface $item): bool
            {
                $this->items[$item->getKey()] = $item;

                return true;
            }

            public function saveDeferred(CacheItemInterface $item): bool
            {
                $this->deferredItems[$item->getKey()] = $item;

                return true;
            }

            public function commit(): bool
            {
                foreach ($this->deferredItems as $item) {
                    $this->save($item);
                }

                $this->deferredItems = [];

                return true;
            }

            private function getTestMemoryCacheItem(string $key)
            {
                return new class($key) implements CacheItemInterface{
                    private $key;
                    private $value;
                    private $expiration;
                    private $isHit = false;

                    public function __construct(string $key)
                    {
                        $this->key = $key;
                    }

                    public function getKey(): string
                    {
                        return $this->key;
                    }

                    public function get(): mixed
                    {
                        return $this->isHit() ? $this->value : null;
                    }

                    public function isHit(): bool
                    {
                        if (!$this->isHit) {
                            return false;
                        }

                        if ($this->expiration === null) {
                            return true;
                        }

                        return $this->currentTime()->getTimestamp() < $this->expiration->getTimestamp();
                    }

                    public function set(mixed $value): static
                    {
                        $this->isHit = true;
                        $this->value = $value;

                        return $this;
                    }

                    public function expiresAt($expiration): static
                    {
                        $this->expiration = $expiration;
                        return $this;
                    }

                    public function expiresAfter($time): static
                    {
                        $this->expiration = $this->currentTime()->add(new \DateInterval("PT{$time}S"));
                        return $this;
                    }

                    protected function currentTime()
                    {
                        return new \DateTime('now', new \DateTimeZone('UTC'));
                    }
                };
            }
        };
    }
}
