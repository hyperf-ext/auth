<?php

declare(strict_types=1);
/**
 * This file is part of hyperf-ext/auth.
 *
 * @link     https://github.com/hyperf-ext/auth
 * @contact  eric@zhu.email
 * @license  https://github.com/hyperf-ext/auth/blob/master/LICENSE
 */
namespace HyperfExt\Auth\Events;

use Psr\Http\Message\ServerRequestInterface;

class Lockout
{
    /**
     * The throttled request.
     *
     * @var \Psr\Http\Message\ServerRequestInterface
     */
    public $request;

    /**
     * Create a new event instance.
     */
    public function __construct(ServerRequestInterface $request)
    {
        $this->request = $request;
    }
}
