<?php

declare(strict_types=1);
/**
 * This file is part of hyperf-ext/auth.
 *
 * @link     https://github.com/hyperf-ext/auth
 * @contact  eric@zhu.email
 * @license  https://github.com/hyperf-ext/auth/blob/master/LICENSE
 */
namespace HyperfTest;

use HyperfExt\Auth\Authenticatable;
use HyperfExt\Auth\Contracts\AuthenticatableInterface;
use PHPUnit\Framework\TestCase;

/**
 * @internal
 * @coversNothing
 */
class AuthenticatableTest extends TestCase
{
    public function testItReturnsSameRememberTokenForString()
    {
        $user = new AuthenticatableUser();
        $user->setRememberToken('sample_token');
        $this->assertSame('sample_token', $user->getRememberToken());
    }

    public function testItReturnsNullWhenRememberTokenNameWasSetToEmpty()
    {
        $user = new class() extends AuthenticatableUser {
            public function getRememberTokenName(): string
            {
                return '';
            }
        };
        $user->setRememberToken('1');
        $this->assertNull($user->getRememberToken());
    }
}

class AuthenticatableUser implements AuthenticatableInterface
{
    use Authenticatable;

    public function getAuthIdentifierName(): string
    {
        return '';
    }

    public function getAuthPassword(): ?string
    {
        return '';
    }
}
