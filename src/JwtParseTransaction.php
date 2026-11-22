<?php

namespace Firebase\JWT;

use DateTime;

/**
 * State captured for a single JWT decode transaction.
 *
 * Keeping this state in one object ensures that a retry or a clock/leeway
 * change made while decode() is running cannot mix values from different
 * snapshots into the same validation result or exception.
 *
 * @internal
 */
final class JwtParseTransaction
{
    /** @var int */
    private $timestamp;

    /** @var int */
    private $leeway;

    /**
     * @param int $timestamp
     * @param int $leeway
     */
    private function __construct(int $timestamp, int $leeway)
    {
        $this->timestamp = $timestamp;
        $this->leeway = $leeway;
    }

    /**
     * @param mixed $leeway Public static properties are not type-hinted in JWT.
     */
    public static function capture(?int $timestamp, $leeway): self
    {
        return new self(
            $timestamp ?? \time(),
            (int) $leeway
        );
    }

    public function validateTimeClaims(stdClass $payload): void
    {
        // Check the nbf if it is defined. This is the time that the
        // token can actually be used. If it's not yet that time, abort.
        if (isset($payload->nbf) && \floor($payload->nbf) > ($this->timestamp + $this->leeway)) {
            $exception = new BeforeValidException(
                'Cannot handle token with nbf prior to '
                . \date(DateTime::ATOM, (int) \floor($payload->nbf))
            );
            $exception->setPayload($payload);

            throw $exception;
        }

        // Check that this token has been created before 'now'. This prevents
        // using tokens that have been created for later use (and haven't
        // correctly used the nbf claim).
        if (!isset($payload->nbf) && isset($payload->iat)
            && \floor($payload->iat) > ($this->timestamp + $this->leeway)
        ) {
            $exception = new BeforeValidException(
                'Cannot handle token with iat prior to '
                . \date(DateTime::ATOM, (int) \floor($payload->iat))
            );
            $exception->setPayload($payload);

            throw $exception;
        }

        // Check if this token has expired.
        if (isset($payload->exp) && ($this->timestamp - $this->leeway) >= $payload->exp) {
            $exception = new ExpiredException('Expired token');
            $exception->setPayload($payload);
            $exception->setTimestamp($this->timestamp);

            throw $exception;
        }
    }
}
