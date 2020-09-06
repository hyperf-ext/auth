<?php

declare(strict_types=1);
/**
 * This file is part of hyperf-ext/auth.
 *
 * @link     https://github.com/hyperf-ext/auth
 * @contact  eric@zhu.email
 * @license  https://github.com/hyperf-ext/auth/blob/master/LICENSE
 */
namespace HyperfExt\Auth\Access;

trait HandlesAuthorization
{
    /**
     * Create a new access response.
     *
     * @param null|mixed $code
     */
    protected function allow(?string $message = null, $code = null): Response
    {
        return Response::allow($message, $code);
    }

    /**
     * Throws an unauthorized exception.
     *
     * @param null|mixed $code
     */
    protected function deny(?string $message = null, $code = null): Response
    {
        return Response::deny($message, $code);
    }
}
