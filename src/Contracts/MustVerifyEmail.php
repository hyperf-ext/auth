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

/**
 * @todo 移植 illuminate 相关组件以实现功能特性
 */
interface MustVerifyEmail
{
    /**
     * Determine if the user has verified their email address.
     */
    public function hasVerifiedEmail(): bool;

    /**
     * Mark the given user's email as verified.
     */
    public function markEmailAsVerified(): bool;

    /**
     * Send the email verification notification.
     */
    public function sendEmailVerificationNotification(): void;

    /**
     * Get the email address that should be used for verification.
     */
    public function getEmailForVerification(): string;
}
