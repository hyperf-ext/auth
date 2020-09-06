<?php

declare(strict_types=1);
/**
 * This file is part of hyperf-ext/auth.
 *
 * @link     https://github.com/hyperf-ext/auth
 * @contact  eric@zhu.email
 * @license  https://github.com/hyperf-ext/auth/blob/master/LICENSE
 */
namespace HyperfExt\Auth;

use Hyperf\Utils\Context;

trait ContextHelpers
{
    public function setContext(string $id, $value)
    {
        Context::set(static::class . '.' . $id, $value);
        return $value;
    }

    public function getContext(string $id, $default = null, $coroutineId = null)
    {
        return Context::get(static::class . '.' . $id, $default, $coroutineId);
    }
}
