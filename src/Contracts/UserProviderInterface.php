<?php

declare(strict_types=1);
/**
 * This file is part of hyperf-ext/auth.
 *
 * @link     https://github.com/hyperf-ext/auth
 * @contact  eric@zhu.email
 * @license  https://github.com/hyperf-ext/auth/blob/master/LICENSE
 */
namespace HyperfExt\Auth\Contracts;

interface UserProviderInterface
{
    /**
     * Retrieve a user by their unique identifier.
     *
     * @param mixed $identifier
     *
     * @return null|\HyperfExt\Auth\Contracts\AuthenticatableInterface
     */
    public function retrieveById($identifier): ?AuthenticatableInterface;

    /**
     * Retrieve a user by their unique identifier and "remember me" token.
     *
     * @param mixed $identifier
     *
     * @return null|\HyperfExt\Auth\Contracts\AuthenticatableInterface
     */
    public function retrieveByToken($identifier, string $token): ?AuthenticatableInterface;

    /**
     * Update the "remember me" token for the given user in storage.
     *
     * @param \HyperfExt\Auth\Contracts\AuthenticatableInterface $user
     */
    public function updateRememberToken(AuthenticatableInterface $user, string $token): void;

    /**
     * Retrieve a user by the given credentials.
     *
     * @return null|\HyperfExt\Auth\Contracts\AuthenticatableInterface
     */
    public function retrieveByCredentials(array $credentials): ?AuthenticatableInterface;

    /**
     * Validate a user against the given credentials.
     *
     * @param \HyperfExt\Auth\Contracts\AuthenticatableInterface $user
     */
    public function validateCredentials(AuthenticatableInterface $user, array $credentials): bool;
}
