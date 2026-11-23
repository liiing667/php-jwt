<?php

namespace Firebase\JWT;

use DateTime;
use stdClass;
use UnexpectedValueException;

/**
 * State captured for a single JWT decode transaction.
 *
 * The compact token is split and its JSON documents are decoded once. The
 * resulting header, payload, signature and claim checks are then shared by
 * every consumer in the decode path, so a retry cannot mix values from another
 * token or another parse into the current result.
 *
 * @internal
 */
final class JwtParseTransaction
{
    /** @var mixed */
    private $header;

    private stdClass $payload;

    private string $signingInput;

    private string $cryptob64;

    /** @var class-string<JWT> */
    private string $jwtClass;

    /**
     * @param mixed $header
     */
    private function __construct(
        $header,
        stdClass $payload,
        string $signingInput,
        string $cryptob64,
        string $jwtClass
    ) {
        $this->header = $header;
        $this->payload = $payload;
        $this->signingInput = $signingInput;
        $this->cryptob64 = $cryptob64;
        $this->jwtClass = $jwtClass;
    }

    /**
     * Parse a compact JWT once for the current decode operation.
     *
     * @param class-string<JWT> $jwtClass
     * @param null|callable(mixed):void $onHeader
     */
    public static function capture(
        string $jwt,
        string $jwtClass = JWT::class,
        ?callable $onHeader = null
    ): self {
        $tks = \explode('.', $jwt, 4);
        if (\count($tks) !== 3) {
            throw new UnexpectedValueException('Wrong number of segments');
        }

        list($headb64, $bodyb64, $cryptob64) = $tks;
        $header = $jwtClass::jsonDecode($jwtClass::urlsafeB64Decode($headb64));
        if (null === $header) {
            throw new UnexpectedValueException('Invalid header encoding');
        }
        $header = self::copy($header);
        if (null !== $onHeader) {
            $onHeader($header);
        }

        $payload = $jwtClass::jsonDecode($jwtClass::urlsafeB64Decode($bodyb64));
        if (null === $payload) {
            throw new UnexpectedValueException('Invalid claims encoding');
        }
        if (\is_array($payload)) {
            // prevent PHP Fatal Error in edge-cases when payload is empty array
            $payload = (object) $payload;
        }
        if (!$payload instanceof stdClass) {
            throw new UnexpectedValueException('Payload must be a JSON object');
        }
        $payload = self::copy($payload);

        return new self(
            $header,
            $payload,
            "{$headb64}.{$bodyb64}",
            $cryptob64,
            $jwtClass
        );
    }

    /**
     * @return mixed
     */
    public function header()
    {
        return $this->header;
    }

    public function payload(): stdClass
    {
        return $this->payload;
    }

    /**
     * Freeze the parsed claims before attaching them to an exception.
     */
    public function payloadSnapshot(): stdClass
    {
        return self::copy($this->payload);
    }

    public function signingInput(): string
    {
        return $this->signingInput;
    }

    public function signature(): string
    {
        return $this->jwtClass::urlsafeB64Decode($this->cryptob64);
    }

    public function validateClaimTypes(): void
    {
        if (isset($this->payload->iat) && !\is_numeric($this->payload->iat)) {
            throw new UnexpectedValueException('Payload iat must be a number');
        }
        if (isset($this->payload->nbf) && !\is_numeric($this->payload->nbf)) {
            throw new UnexpectedValueException('Payload nbf must be a number');
        }
        if (isset($this->payload->exp) && !\is_numeric($this->payload->exp)) {
            throw new UnexpectedValueException('Payload exp must be a number');
        }
    }

    /**
     * @param int|float $timestamp
     * @param int|float $leeway
     */
    public function validateTimeClaims($timestamp, $leeway): void
    {
        // Check the nbf if it is defined. This is the time that the
        // token can actually be used. If it's not yet that time, abort.
        if (isset($this->payload->nbf) && \floor($this->payload->nbf) > ($timestamp + $leeway)) {
            $exception = new BeforeValidException(
                'Cannot handle token with nbf prior to '
                . \date(DateTime::ATOM, (int) \floor($this->payload->nbf))
            );
            $exception->setPayload($this->payloadSnapshot());

            throw $exception;
        }

        // Check that this token has been created before 'now'. This prevents
        // using tokens that have been created for later use (and haven't
        // correctly used the nbf claim).
        if (!isset($this->payload->nbf) && isset($this->payload->iat)
            && \floor($this->payload->iat) > ($timestamp + $leeway)
        ) {
            $exception = new BeforeValidException(
                'Cannot handle token with iat prior to '
                . \date(DateTime::ATOM, (int) \floor($this->payload->iat))
            );
            $exception->setPayload($this->payloadSnapshot());

            throw $exception;
        }

        // Check if this token has expired.
        if (isset($this->payload->exp) && ($timestamp - $leeway) >= $this->payload->exp) {
            $exception = new ExpiredException('Expired token');
            $exception->setPayload($this->payloadSnapshot());
            $exception->setTimestamp($timestamp);

            throw $exception;
        }
    }

    public function createSignatureInvalidException(): SignatureInvalidException
    {
        $exception = new SignatureInvalidException('Signature verification failed');
        $exception->setPayload($this->payloadSnapshot());

        return $exception;
    }

    /**
     * @template T
     * @param T $value
     * @return T
     */
    private static function copy($value)
    {
        if ($value instanceof stdClass) {
            $copy = new stdClass();
            foreach (\get_object_vars($value) as $key => $item) {
                $copy->{$key} = self::copy($item);
            }

            return $copy;
        }

        if (\is_array($value)) {
            $copy = [];
            foreach ($value as $key => $item) {
                $copy[$key] = self::copy($item);
            }

            return $copy;
        }

        return $value;
    }
}
