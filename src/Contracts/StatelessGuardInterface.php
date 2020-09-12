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

interface StatelessGuardInterface extends GuardInterface
{
    /**
     * Attempt to authenticate the user using the given credentials and return the token.
     *
     * @return bool|mixed
     */
    public function attempt(array $credentials = [], bool $login = true);

    /**
     * Log a user into the application without sessions or cookies.
     */
    public function once(array $credentials = []): bool;

    /**
     * Log a user into the application, create a token for the user.
     *
     * @return mixed
     */
    public function login(AuthenticatableInterface $user);

    /**
     * Log the given user ID into the application.
     *
     * @param mixed $id
     *
     * @return false|mixed
     */
    public function loginUsingId($id);

    /**
     * Log the given user ID into the application without sessions or cookies.
     *
     * @param mixed $id
     */
    public function onceUsingId($id): bool;

    /**
     * Log the user out of the application, thus invalidating the token.
     */
    public function logout(bool $forceForever = false);

    /**
     * Refresh the token.
     *
     * @return mixed
     */
    public function refresh(bool $forceForever = false);

    /**
     * Invalidate the token.
     *
     * @return mixed
     */
    public function invalidate(bool $forceForever = false);
}
