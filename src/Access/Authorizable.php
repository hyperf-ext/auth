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

use Hyperf\Utils\ApplicationContext;
use HyperfExt\Auth\Contracts\Access\GateManagerInterface;

trait Authorizable
{
    /**
     * Determine if the entity has the given abilities.
     *
     * @param iterable|string $abilities
     * @param array|mixed $arguments
     */
    public function can($abilities, $arguments = []): bool
    {
        return ApplicationContext::getContainer()
            ->get(GateManagerInterface::class)
            ->forUser($this)
            ->check($abilities, $arguments);
    }

    /**
     * Determine if the entity does not have the given abilities.
     *
     * @param iterable|string $abilities
     * @param array|mixed $arguments
     */
    public function cant($abilities, $arguments = []): bool
    {
        return ! $this->can($abilities, $arguments);
    }

    /**
     * Determine if the entity does not have the given abilities.
     *
     * @param iterable|string $abilities
     * @param array|mixed $arguments
     */
    public function cannot($abilities, $arguments = []): bool
    {
        return $this->cant($abilities, $arguments);
    }
}
