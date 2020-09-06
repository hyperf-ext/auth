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

interface AuthenticatableInterface
{
    /**
     * Get the name of the unique identifier for the user.
     */
    public function getAuthIdentifierName(): string;

    /**
     * Get the unique identifier for the user.
     *
     * @return mixed
     */
    public function getAuthIdentifier();

    /**
     * Get the password for the user.
     */
    public function getAuthPassword(): ?string;

    /**
     * Get the token value for the "remember me" session.
     */
    public function getRememberToken(): ?string;

    /**
     * Set the token value for the "remember me" session.
     */
    public function setRememberToken(string $value);

    /**
     * Get the column name for the "remember me" token.
     */
    public function getRememberTokenName(): ?string;
}
