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

interface SupportsBasicAuthInterface
{
    /**
     * Attempt to authenticate using HTTP Basic Auth.
     */
    public function basic(string $field = 'email', array $extraConditions = []): void;

    /**
     * Perform a stateless HTTP Basic login attempt.
     */
    public function onceBasic(string $field = 'email', array $extraConditions = []): void;
}
