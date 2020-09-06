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

interface PasswordBrokerManagerInterface
{
    /**
     * Get a password broker instance by name.
     *
     * @return mixed
     */
    public function broker(?string $name = null);
}
