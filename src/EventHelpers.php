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

use HyperfExt\Auth\Contracts\AuthenticatableInterface;
use HyperfExt\Auth\Events\Attempting;
use HyperfExt\Auth\Events\Authenticated;
use HyperfExt\Auth\Events\CurrentDeviceLogout;
use HyperfExt\Auth\Events\Failed;
use HyperfExt\Auth\Events\Login;
use HyperfExt\Auth\Events\Logout;
use HyperfExt\Auth\Events\OtherDeviceLogout;
use HyperfExt\Auth\Events\Validated;

trait EventHelpers
{
    /**
     * Fire the attempt event with the arguments.
     */
    protected function dispatchAttemptingEvent(array $credentials, bool $remember = false): void
    {
        $this->eventDispatcher->dispatch(new Attempting(
            $this->name,
            $credentials,
            $remember
        ));
    }

    /**
     * Fires the validated event if the dispatcher is set.
     */
    protected function dispatchValidatedEvent(AuthenticatableInterface $user)
    {
        $this->eventDispatcher->dispatch(new Validated(
            $this->name,
            $user
        ));
    }

    /**
     * Fire the login event if the dispatcher is set.
     */
    protected function dispatchLoginEvent(AuthenticatableInterface $user, bool $remember = false): void
    {
        $this->eventDispatcher->dispatch(new Login(
            $this->name,
            $user,
            $remember
        ));
    }

    /**
     * Fire the authenticated event if the dispatcher is set.
     */
    protected function dispatchAuthenticatedEvent(AuthenticatableInterface $user): void
    {
        $this->eventDispatcher->dispatch(new Authenticated(
            $this->name,
            $user
        ));
    }

    /**
     * Fire the logout event if the dispatcher is set.
     */
    protected function dispatchLogoutEvent(AuthenticatableInterface $user): void
    {
        $this->eventDispatcher->dispatch(new Logout(
            $this->name,
            $user
        ));
    }

    /**
     * Fire the current device logout event if the dispatcher is set.
     */
    protected function dispatchCurrentDeviceLogoutEvent(AuthenticatableInterface $user): void
    {
        $this->eventDispatcher->dispatch(new CurrentDeviceLogout(
            $this->name,
            $user
        ));
    }

    /**
     * Fire the other device logout event if the dispatcher is set.
     */
    protected function dispatchOtherDeviceLogoutEvent(AuthenticatableInterface $user): void
    {
        $this->eventDispatcher->dispatch(new OtherDeviceLogout(
            $this->name,
            $user
        ));
    }

    /**
     * Fire the failed authentication attempt event with the given arguments.
     */
    protected function dispatchFailedEvent(?AuthenticatableInterface $user, array $credentials): void
    {
        $this->eventDispatcher->dispatch(new Failed(
            $this->name,
            $user,
            $credentials
        ));
    }
}
