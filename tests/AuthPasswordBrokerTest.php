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

use Hyperf\Utils\Arr;
use HyperfExt\Auth\Contracts\AuthenticatableInterface;
use HyperfExt\Auth\Contracts\CanResetPasswordInterface;
use HyperfExt\Auth\Contracts\PasswordBrokerInterface;
use HyperfExt\Auth\Contracts\TokenRepositoryInterface;
use HyperfExt\Auth\Contracts\UserProviderInterface;
use HyperfExt\Auth\Passwords\PasswordBroker;
use Mockery as m;
use PHPUnit\Framework\TestCase;
use UnexpectedValueException;

/**
 * @internal
 * @coversNothing
 */
class AuthPasswordBrokerTest extends TestCase
{
    protected function tearDown(): void
    {
        m::close();
    }

    public function testIfUserIsNotFoundErrorRedirectIsReturned()
    {
        $mocks = $this->getMocks();
        $broker = $this->getMockBuilder(PasswordBroker::class)->setMethods(['getUser', 'makeErrorRedirect'])->setConstructorArgs(array_values($mocks))->getMock();
        $broker->expects($this->once())->method('getUser')->willReturn(null);

        $this->assertEquals(PasswordBrokerInterface::INVALID_USER, $broker->sendResetLink(['credentials']));
    }

    public function testIfTokenIsRecentlyCreated()
    {
        $mocks = $this->getMocks();
        $broker = $this->getMockBuilder(PasswordBroker::class)->setMethods(['emailResetLink', 'getUri'])->setConstructorArgs(array_values($mocks))->getMock();
        $mocks['users']->shouldReceive('retrieveByCredentials')->once()->with(['foo'])->andReturn($user = m::mock(AuthenticatableInterface::class, CanResetPasswordInterface::class));
        $mocks['tokens']->shouldReceive('recentlyCreatedToken')->once()->with($user)->andReturn(true);
        $user->shouldReceive('sendPasswordResetNotification')->with('token');

        $this->assertEquals(PasswordBrokerInterface::RESET_THROTTLED, $broker->sendResetLink(['foo']));
    }

    public function testGetUserThrowsExceptionIfUserDoesntImplementCanResetPassword()
    {
        $this->expectException(UnexpectedValueException::class);
        $this->expectExceptionMessage('User must implement CanResetPassword interface.');

        $broker = $this->getBroker($mocks = $this->getMocks());
        $mocks['users']->shouldReceive('retrieveByCredentials')->once()->with(['foo'])->andReturn(m::mock(AuthenticatableInterface::class));

        $broker->getUser(['foo']);
    }

    public function testUserIsRetrievedByCredentials()
    {
        $broker = $this->getBroker($mocks = $this->getMocks());
        $mocks['users']->shouldReceive('retrieveByCredentials')->once()->with(['foo'])->andReturn($user = m::mock(AuthenticatableInterface::class, CanResetPasswordInterface::class));

        $this->assertEquals($user, $broker->getUser(['foo']));
    }

    public function testBrokerCreatesTokenAndRedirectsWithoutError()
    {
        $mocks = $this->getMocks();
        $broker = $this->getMockBuilder(PasswordBroker::class)->setMethods(['emailResetLink', 'getUri'])->setConstructorArgs(array_values($mocks))->getMock();
        $mocks['users']->shouldReceive('retrieveByCredentials')->once()->with(['foo'])->andReturn($user = m::mock(AuthenticatableInterface::class, CanResetPasswordInterface::class));
        $mocks['tokens']->shouldReceive('recentlyCreatedToken')->once()->with($user)->andReturn(false);
        $mocks['tokens']->shouldReceive('create')->once()->with($user)->andReturn('token');
        $user->shouldReceive('sendPasswordResetNotification')->with('token');

        $this->assertEquals(PasswordBrokerInterface::RESET_LINK_SENT, $broker->sendResetLink(['foo']));
    }

    public function testRedirectIsReturnedByResetWhenUserCredentialsInvalid()
    {
        $broker = $this->getBroker($mocks = $this->getMocks());
        $mocks['users']->shouldReceive('retrieveByCredentials')->once()->with(['creds'])->andReturn(null);

        $this->assertEquals(PasswordBrokerInterface::INVALID_USER, $broker->reset(['creds'], function () {
        }));
    }

    public function testRedirectReturnedByRemindWhenRecordDoesntExistInTable()
    {
        $creds = ['token' => 'token'];
        $broker = $this->getBroker($mocks = $this->getMocks());
        $mocks['users']->shouldReceive('retrieveByCredentials')->once()->with(Arr::except($creds, ['token']))->andReturn($user = m::mock(AuthenticatableInterface::class, CanResetPasswordInterface::class));
        $mocks['tokens']->shouldReceive('exists')->with($user, 'token')->andReturn(false);

        $this->assertEquals(PasswordBrokerInterface::INVALID_TOKEN, $broker->reset($creds, function () {
        }));
    }

    public function testResetRemovesRecordOnReminderTableAndCallsCallback()
    {
        unset($_SERVER['__password.reset.test']);
        $broker = $this->getMockBuilder(PasswordBroker::class)->setMethods(['validateReset', 'getPassword', 'getToken'])->setConstructorArgs(array_values($mocks = $this->getMocks()))->getMock();
        $broker->expects($this->once())->method('validateReset')->willReturn($user = m::mock(AuthenticatableInterface::class, CanResetPasswordInterface::class));
        $mocks['tokens']->shouldReceive('delete')->once()->with($user);
        $callback = function ($user, $password) {
            $_SERVER['__password.reset.test'] = compact('user', 'password');

            return 'foo';
        };

        $this->assertEquals(PasswordBrokerInterface::PASSWORD_RESET, $broker->reset(['password' => 'password', 'token' => 'token'], $callback));
        $this->assertEquals(['user' => $user, 'password' => 'password'], $_SERVER['__password.reset.test']);
    }

    protected function getBroker($mocks)
    {
        return new PasswordBroker($mocks['tokens'], $mocks['users']);
    }

    protected function getMocks()
    {
        return [
            'tokens' => m::mock(TokenRepositoryInterface::class),
            'users' => m::mock(UserProviderInterface::class),
            //            'mailer' => m::mock(Mailer::class),
            //            'view'   => 'resetLinkView',
        ];
    }
}
