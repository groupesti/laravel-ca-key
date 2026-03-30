<?php

declare(strict_types=1);

namespace CA\Key\Services;

use CA\Exceptions\InvalidKeyException;
use CA\Key\Contracts\KeyGeneratorInterface;
use CA\Log\Facades\CaLog;
use CA\Models\KeyAlgorithm;

final class KeyGenerator
{
    /** @var array<string, KeyGeneratorInterface> */
    private array $generators = [];

    /**
     * Register a generator for a given algorithm.
     */
    public function register(KeyGeneratorInterface $generator): void
    {
        $this->generators[$generator->getAlgorithm()] = $generator;
    }

    /**
     * Resolve the correct generator for the given algorithm.
     *
     * @throws InvalidKeyException
     */
    public function resolve(KeyAlgorithm $algorithm): KeyGeneratorInterface
    {
        $slug = (string) $algorithm;

        foreach ($this->generators as $generator) {
            if ($generator->supports($slug)) {
                return $generator;
            }
        }

        throw new InvalidKeyException(
            "No generator registered for algorithm: {$slug}"
        );
    }

    /**
     * Generate a key pair for the given algorithm.
     *
     * @param  array<string, mixed>  $parameters
     * @return array{privateKey: \phpseclib3\Crypt\Common\PrivateKey, publicKey: \phpseclib3\Crypt\Common\PublicKey}
     *
     * @throws InvalidKeyException
     */
    public function generate(KeyAlgorithm $algorithm, array $parameters = []): array
    {
        try {
            $result = $this->resolve($algorithm)->generate($parameters);

            CaLog::keyGenerated(
                algorithm: (string) $algorithm,
                keySize: $algorithm->getKeySize() ?? 0,
                context: ['parameters' => $parameters],
            );

            return $result;
        } catch (\Throwable $e) {
            CaLog::critical($e->getMessage(), [
                'operation' => 'key_generation',
                'algorithm' => (string) $algorithm,
                'exception' => $e::class,
            ]);

            throw $e;
        }
    }

    /**
     * Check if an algorithm is supported.
     */
    public function supports(KeyAlgorithm $algorithm): bool
    {
        $slug = (string) $algorithm;

        foreach ($this->generators as $generator) {
            if ($generator->supports($slug)) {
                return true;
            }
        }

        return false;
    }
}
