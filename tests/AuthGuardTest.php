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

use Hyperf\Contract\SessionInterface;
use Hyperf\HttpMessage\Cookie\Cookie;
use Hyperf\HttpMessage\Uri\Uri;
use Hyperf\HttpServer\Request;
use Hyperf\Utils\Context;
use HyperfExt\Auth\Contracts\AuthenticatableInterface;
use HyperfExt\Auth\Contracts\UserProviderInterface;
use HyperfExt\Auth\Events\Attempting;
use HyperfExt\Auth\Events\Authenticated;
use HyperfExt\Auth\Events\CurrentDeviceLogout;
use HyperfExt\Auth\Events\Failed;
use HyperfExt\Auth\Events\Login;
use HyperfExt\Auth\Events\Logout;
use HyperfExt\Auth\Events\Validated;
use HyperfExt\Auth\Exceptions\AuthenticationException;
use HyperfExt\Auth\Guards\SessionGuard;
use HyperfExt\Auth\Recaller;
use HyperfExt\Cookie\CookieJar;
use Mockery as m;
use PHPUnit\Framework\TestCase;
use Psr\EventDispatcher\EventDispatcherInterface;
use Psr\Http\Message\ServerRequestInterface;

/**
 * @internal
 * @coversNothing
 */
class AuthGuardTest extends TestCase
{
    protected function tearDown(): void
    {
        m::close();
    }

    public function testBasicReturnsNullOnValidAttempt()
    {
        $guard = m::mock(SessionGuard::class . '[check,attempt]', [$request, $session, $events, $cookies, $provider, $options] = $this->getMocks());
        $guard->shouldReceive('check')->once()->andReturn(false);
        $guard->shouldReceive('attempt')->once()->with(['email' => 'foo@bar.com', 'password' => 'secret'])->andReturn(true);
        Context::set(ServerRequestInterface::class, $request
            ->withMethod('GET')
            ->withUri(new Uri('/'))
            ->withHeader('authorization', 'Basic ' . base64_encode('foo@bar.com:secret')));
        $request = new Request();
        $guard->setRequest($request);

        $this->assertNull($guard->basic('email'));
    }

    public function testBasicReturnsNullWhenAlreadyLoggedIn()
    {
        $guard = m::mock(SessionGuard::class . '[check]', [$request, $session, $events, $cookies, $provider, $options] = $this->getMocks());
        $guard->shouldReceive('check')->once()->andReturn(true);
        $guard->shouldReceive('attempt')->never();
        Context::set(ServerRequestInterface::class, $request
            ->withMethod('GET')
            ->withUri(new Uri('/'))
            ->withHeader('authorization', 'Basic ' . base64_encode('foo@bar.com:secret')));
        $request = new Request();
        $guard->setRequest($request);

        $this->assertNull($guard->basic('email'));
    }

    public function testBasicReturnsResponseOnFailure()
    {
        $this->expectException(AuthenticationException::class);

        $guard = m::mock(SessionGuard::class . '[check,attempt]', [$request, $session, $events, $cookies, $provider, $options] = $this->getMocks());
        $guard->shouldReceive('check')->once()->andReturn(false);
        $guard->shouldReceive('attempt')->once()->with(['email' => 'foo@bar.com', 'password' => 'secret'])->andReturn(false);
        Context::set(ServerRequestInterface::class, $request
            ->withMethod('GET')
            ->withUri(new Uri('/'))
            ->withHeader('authorization', 'Basic ' . base64_encode('foo@bar.com:secret')));
        $request = new Request();
        $guard->setRequest($request);
        $guard->basic('email');
    }

    public function testBasicWithExtraConditions()
    {
        $guard = m::mock(SessionGuard::class . '[check,attempt]', [$request, $session, $events, $cookies, $provider, $options] = $this->getMocks());
        $guard->shouldReceive('check')->once()->andReturn(false);
        $guard->shouldReceive('attempt')->once()->with(['email' => 'foo@bar.com', 'password' => 'secret', 'active' => 1])->andReturn(true);
        Context::set(ServerRequestInterface::class, $request
            ->withMethod('GET')
            ->withUri(new Uri('/'))
            ->withHeader('authorization', 'Basic ' . base64_encode('foo@bar.com:secret')));
        $request = new Request();
        $guard->setRequest($request);

        $this->assertNull($guard->basic('email', ['active' => 1]));
    }

    public function testBasicWithExtraArrayConditions()
    {
        $guard = m::mock(SessionGuard::class . '[check,attempt]', [$request, $session, $events, $cookies, $provider, $options] = $this->getMocks());
        $guard->shouldReceive('check')->once()->andReturn(false);
        $guard->shouldReceive('attempt')->once()->with(['email' => 'foo@bar.com', 'password' => 'secret', 'active' => 1, 'type' => [1, 2, 3]])->andReturn(true);
        Context::set(ServerRequestInterface::class, $request
            ->withMethod('GET')
            ->withUri(new Uri('/'))
            ->withHeader('authorization', 'Basic ' . base64_encode('foo@bar.com:secret')));
        $request = new Request();
        $guard->setRequest($request);

        $this->assertNull($guard->basic('email', ['active' => 1, 'type' => [1, 2, 3]]));
    }

    public function testAttemptCallsRetrieveByCredentials()
    {
        $guard = $this->getGuard();
        $events = $guard->getEventDispatcher();
        $events->shouldReceive('dispatch')->once()->with(m::type(Attempting::class));
        $events->shouldReceive('dispatch')->once()->with(m::type(Failed::class));
        $events->shouldNotReceive('dispatch')->with(m::type(Validated::class));
        $guard->getProvider()->shouldReceive('retrieveByCredentials')->once()->with(['foo']);
        $this->assertFalse($guard->attempt(['foo']));
    }

    public function testAttemptReturnsUserInterface()
    {
        $guard = $this->getMockBuilder(SessionGuard::class)->setMethods(['login'])->setConstructorArgs([$request, $session, $events, $cookies, $provider, $options] = $this->getMocks())->getMock();
        $events->shouldReceive('dispatch')->once()->with(m::type(Attempting::class));
        $events->shouldReceive('dispatch')->once()->with(m::type(Validated::class));
        $user = $this->createMock(AuthenticatableInterface::class);
        $guard->getProvider()->shouldReceive('retrieveByCredentials')->once()->andReturn($user);
        $guard->getProvider()->shouldReceive('validateCredentials')->with($user, ['foo'])->andReturn(true);
        $guard->expects($this->once())->method('login')->with($this->equalTo($user));
        $this->assertTrue($guard->attempt(['foo']));
    }

    public function testAttemptReturnsFalseIfUserNotGiven()
    {
        $mock = $this->getGuard();
        $events = $mock->getEventDispatcher();
        $events->shouldReceive('dispatch')->once()->with(m::type(Attempting::class));
        $events->shouldReceive('dispatch')->once()->with(m::type(Failed::class));
        $events->shouldNotReceive('dispatch')->with(m::type(Validated::class));
        $mock->getProvider()->shouldReceive('retrieveByCredentials')->once()->andReturn(null);
        $this->assertFalse($mock->attempt(['foo']));
    }

    public function testLoginStoresIdentifierInSession()
    {
        $mock = $this->getMockBuilder(SessionGuard::class)->setConstructorArgs([$request, $session, $events, $cookies, $provider, $options] = $this->getMocks())->setMethods(['getName'])->getMock();
        $user = m::mock(AuthenticatableInterface::class);
        $mock->expects($this->once())->method('getName')->willReturn('foo');
        $user->shouldReceive('getAuthIdentifier')->once()->andReturn('bar');
        $mock->getSession()->shouldReceive('put')->with('foo', 'bar')->once();
        $session->shouldReceive('migrate')->once();
        $events->shouldReceive('dispatch')->once()->with(m::type(Login::class));
        $events->shouldReceive('dispatch')->once()->with(m::type(Authenticated::class));
        $mock->login($user);
    }

    public function testSessionGuardIsMacroable()
    {
        $guard = $this->getGuard();

        $guard->macro('foo', function () {
            return 'bar';
        });

        $this->assertSame(
            'bar',
            $guard->foo()
        );
    }

    public function testLoginFiresLoginAndAuthenticatedEvents()
    {
        $mock = $this->getMockBuilder(SessionGuard::class)->setMethods(['getName'])->setConstructorArgs([$request, $session, $events, $cookies, $provider, $options] = $this->getMocks())->getMock();
        $user = m::mock(AuthenticatableInterface::class);
        $events->shouldReceive('dispatch')->once()->with(m::type(Login::class));
        $events->shouldReceive('dispatch')->once()->with(m::type(Authenticated::class));
        $mock->expects($this->once())->method('getName')->willReturn('foo');
        $user->shouldReceive('getAuthIdentifier')->once()->andReturn('bar');
        $mock->getSession()->shouldReceive('put')->with('foo', 'bar')->once();
        $session->shouldReceive('migrate')->once();
        $mock->login($user);
    }

    public function testFailedAttemptFiresFailedEvent()
    {
        $guard = $this->getGuard();
        $events = $guard->getEventDispatcher();
        $events->shouldReceive('dispatch')->once()->with(m::type(Attempting::class));
        $events->shouldReceive('dispatch')->once()->with(m::type(Failed::class));
        $events->shouldNotReceive('dispatch')->with(m::type(Validated::class));
        $guard->getProvider()->shouldReceive('retrieveByCredentials')->once()->with(['foo'])->andReturn(null);
        $this->assertFalse($guard->attempt(['foo']));
    }

    public function testAuthenticateReturnsUserWhenUserIsNotNull()
    {
        $user = m::mock(AuthenticatableInterface::class);
        $guard = $this->getGuard();
        $guard->getEventDispatcher()->shouldReceive('dispatch')->once()->with(m::type(Authenticated::class));
        $guard->setUser($user);

        $this->assertEquals($user, $guard->authenticate());
    }

    public function testSetUserFiresAuthenticatedEvent()
    {
        $user = m::mock(AuthenticatableInterface::class);
        $guard = $this->getGuard();
        $guard->setEventDispatcher($events = m::mock(EventDispatcherInterface::class));
        $events->shouldReceive('dispatch')->once()->with(m::type(Authenticated::class));
        $this->assertNotNull($guard->setUser($user));
    }

    public function testAuthenticateThrowsWhenUserIsNull()
    {
        $this->expectException(AuthenticationException::class);
        $this->expectExceptionMessage('Unauthenticated.');

        $guard = $this->getGuard();
        $guard->getSession()->shouldReceive('get')->once()->andReturn(null);

        $guard->authenticate();
    }

    public function testHasUserReturnsTrueWhenUserIsNotNull()
    {
        $user = m::mock(AuthenticatableInterface::class);
        $guard = $this->getGuard();
        $guard->getEventDispatcher()->shouldReceive('dispatch')->once()->with(m::type(Authenticated::class));
        $guard->setUser($user);

        $this->assertTrue($guard->hasUser());
    }

    public function testHasUserReturnsFalseWhenUserIsNull()
    {
        $guard = $this->getGuard();
        $guard->getSession()->shouldNotReceive('get');

        $this->assertFalse($guard->hasUser());
    }

    public function testIsAuthedReturnsTrueWhenUserIsNotNull()
    {
        $user = m::mock(AuthenticatableInterface::class);
        $mock = $this->getGuard();
        $mock->getEventDispatcher()->shouldReceive('dispatch')->once()->with(m::type(Authenticated::class));
        $mock->setUser($user);
        $this->assertTrue($mock->check());
        $this->assertFalse($mock->guest());
    }

    public function testIsAuthedReturnsFalseWhenUserIsNull()
    {
        $mock = $this->getMockBuilder(SessionGuard::class)->setMethods(['user'])->setConstructorArgs([$request, $session, $events, $cookies, $provider, $options] = $this->getMocks())->getMock();
        $mock->expects($this->exactly(2))->method('user')->willReturn(null);
        $this->assertFalse($mock->check());
        $this->assertTrue($mock->guest());
    }

    public function testUserMethodReturnsCachedUser()
    {
        $user = m::mock(AuthenticatableInterface::class);
        $mock = $this->getGuard();
        $mock->getEventDispatcher()->shouldReceive('dispatch')->once()->with(m::type(Authenticated::class));
        $mock->setUser($user);
        $this->assertSame($user, $mock->user());
    }

    public function testNullIsReturnedForUserIfNoUserFound()
    {
        $mock = $this->getGuard();
        $mock->getSession()->shouldReceive('get')->once()->andReturn(null);
        $this->assertNull($mock->user());
    }

    public function testUserIsSetToRetrievedUser()
    {
        $mock = $this->getGuard();
        $mock->getSession()->shouldReceive('get')->once()->andReturn(1);
        $mock->getEventDispatcher()->shouldReceive('dispatch')->once()->with(m::type(Authenticated::class));
        $user = m::mock(AuthenticatableInterface::class);
        $mock->getProvider()->shouldReceive('retrieveById')->once()->with(1)->andReturn($user);
        $this->assertSame($user, $mock->user());
        $this->assertSame($user, $mock->getUser());
    }

    public function testLogoutRemovesSessionTokenAndRememberMeCookie()
    {
        $mock = $this->getMockBuilder(SessionGuard::class)->setMethods(['getName', 'getRecallerName', 'recaller'])->setConstructorArgs([$request, $session, $events, $cookies, $provider, $options] = $this->getMocks())->getMock();
        $user = m::mock(AuthenticatableInterface::class);
        $user->shouldReceive('getRememberToken')->once()->andReturn('a');
        $user->shouldReceive('setRememberToken')->once();
        $mock->expects($this->once())->method('getName')->willReturn('foo');
        $mock->expects($this->once())->method('getRecallerName')->willReturn('bar');
        $mock->expects($this->once())->method('recaller')->willReturn(m::mock(Recaller::class));
        $provider->shouldReceive('updateRememberToken')->once();
        $mock->getEventDispatcher()->shouldReceive('dispatch')->once()->with(m::type(Authenticated::class));
        $mock->getEventDispatcher()->shouldReceive('dispatch')->once()->with(m::type(Logout::class));

        $cookie = m::mock(Cookie::class);
        $cookies->shouldReceive('forget')->once()->with('bar')->andReturn($cookie);
        $cookies->shouldReceive('queue')->once()->with($cookie);
        $mock->getSession()->shouldReceive('remove')->once()->with('foo');
        $mock->setUser($user);
        $mock->logout();
        $this->assertNull($mock->getUser());
    }

    public function testLogoutDoesNotEnqueueRememberMeCookieForDeletionIfCookieDoesntExist()
    {
        $mock = $this->getMockBuilder(SessionGuard::class)->setMethods(['getName', 'recaller'])->setConstructorArgs([$request, $session, $events, $cookies, $provider, $options] = $this->getMocks())->getMock();
        $user = m::mock(AuthenticatableInterface::class);
        $user->shouldReceive('getRememberToken')->andReturn(null);
        $mock->expects($this->once())->method('getName')->willReturn('foo');
        $mock->expects($this->once())->method('recaller')->willReturn(null);

        $mock->getSession()->shouldReceive('remove')->once()->with('foo');
        $mock->getEventDispatcher()->shouldReceive('dispatch')->once()->with(m::type(Authenticated::class));
        $mock->setUser($user);
        $mock->getEventDispatcher()->shouldReceive('dispatch')->once()->with(m::type(Logout::class));
        $mock->logout();
        $this->assertNull($mock->getUser());
    }

    public function testLogoutFiresLogoutEvent()
    {
        $mock = $this->getMockBuilder(SessionGuard::class)->setMethods(['clearUserDataFromStorage'])->setConstructorArgs([$request, $session, $events, $cookies, $provider, $options] = $this->getMocks())->getMock();
        $mock->expects($this->once())->method('clearUserDataFromStorage');
        $mock->setEventDispatcher($events = m::mock(EventDispatcherInterface::class));
        $user = m::mock(AuthenticatableInterface::class);
        $user->shouldReceive('getRememberToken')->andReturn(null);
        $events->shouldReceive('dispatch')->once()->with(m::type(Authenticated::class));
        $mock->setUser($user);
        $events->shouldReceive('dispatch')->once()->with(m::type(Logout::class));
        $mock->logout();
    }

    public function testLogoutDoesNotSetRememberTokenIfNotPreviouslySet()
    {
        $mock = $this->getMockBuilder(SessionGuard::class)->setMethods(['clearUserDataFromStorage'])->setConstructorArgs([$request, $session, $events, $cookies, $provider, $options] = $this->getMocks())->getMock();
        $user = m::mock(AuthenticatableInterface::class);

        $user->shouldReceive('getRememberToken')->andReturn(null);
        $user->shouldNotReceive('setRememberToken');
        $provider->shouldNotReceive('updateRememberToken');

        $mock->getEventDispatcher()->shouldReceive('dispatch')->once()->with(m::type(Authenticated::class));
        $mock->setUser($user);
        $events->shouldReceive('dispatch')->once()->with(m::type(Logout::class));
        $this->assertNull($mock->logout());
    }

    public function testLogoutCurrentDeviceRemovesRememberMeCookie()
    {
        $mock = $this->getMockBuilder(SessionGuard::class)->setMethods(['getName', 'getRecallerName', 'recaller'])->setConstructorArgs([$request, $session, $events, $cookies, $provider, $options] = $this->getMocks())->getMock();
        $user = m::mock(AuthenticatableInterface::class);
        $mock->expects($this->once())->method('getName')->willReturn('foo');
        $mock->expects($this->once())->method('getRecallerName')->willReturn('bar');
        $mock->expects($this->once())->method('recaller')->willReturn(m::mock(Recaller::class));

        $cookie = m::mock(Cookie::class);
        $cookies->shouldReceive('forget')->once()->with('bar')->andReturn($cookie);
        $cookies->shouldReceive('queue')->once()->with($cookie);
        $mock->getSession()->shouldReceive('remove')->once()->with('foo');
        $mock->getEventDispatcher()->shouldReceive('dispatch')->once()->with(m::type(Authenticated::class));
        $mock->setUser($user);
        $mock->getEventDispatcher()->shouldReceive('dispatch')->once()->with(m::type(CurrentDeviceLogout::class));
        $mock->logoutCurrentDevice();
        $this->assertNull($mock->getUser());
    }

    public function testLogoutCurrentDeviceDoesNotEnqueueRememberMeCookieForDeletionIfCookieDoesntExist()
    {
        $mock = $this->getMockBuilder(SessionGuard::class)->setMethods(['getName', 'recaller'])->setConstructorArgs([$request, $session, $events, $cookies, $provider, $options] = $this->getMocks())->getMock();
        $user = m::mock(AuthenticatableInterface::class);
        $user->shouldReceive('getRememberToken')->andReturn(null);
        $mock->expects($this->once())->method('getName')->willReturn('foo');
        $mock->expects($this->once())->method('recaller')->willReturn(null);

        $mock->getSession()->shouldReceive('remove')->once()->with('foo');
        $mock->getEventDispatcher()->shouldReceive('dispatch')->once()->with(m::type(Authenticated::class));
        $mock->setUser($user);
        $mock->getEventDispatcher()->shouldReceive('dispatch')->once()->with(m::type(CurrentDeviceLogout::class));
        $mock->logoutCurrentDevice();
        $this->assertNull($mock->getUser());
    }

    public function testLogoutCurrentDeviceFiresLogoutEvent()
    {
        $mock = $this->getMockBuilder(SessionGuard::class)->setMethods(['clearUserDataFromStorage'])->setConstructorArgs([$request, $session, $events, $cookies, $provider, $options] = $this->getMocks())->getMock();
        $mock->expects($this->once())->method('clearUserDataFromStorage');
        $mock->setEventDispatcher($events = m::mock(EventDispatcherInterface::class));
        $user = m::mock(AuthenticatableInterface::class);
        $user->shouldReceive('getRememberToken')->andReturn(null);
        $events->shouldReceive('dispatch')->once()->with(m::type(Authenticated::class));
        $mock->setUser($user);
        $events->shouldReceive('dispatch')->once()->with(m::type(CurrentDeviceLogout::class));
        $mock->logoutCurrentDevice();
    }

    public function testLoginMethodQueuesCookieWhenRemembering()
    {
        $guard = $this->getGuard();
        $cookies = $guard->getCookieJar();
        $session = $guard->getSession();
        $provider = $guard->getProvider();
        $events = $guard->getEventDispatcher();
        $foreverCookie = new Cookie($guard->getRecallerName(), 'foo');
        $cookies->shouldReceive('forever')->once()->with($guard->getRecallerName(), 'foo|recaller|bar')->andReturn($foreverCookie);
        $cookies->shouldReceive('queue')->once()->with($foreverCookie);
        $guard->getSession()->shouldReceive('put')->once()->with($guard->getName(), 'foo');
        $session->shouldReceive('migrate')->once();
        $user = m::mock(AuthenticatableInterface::class);
        $user->shouldReceive('getAuthIdentifier')->andReturn('foo');
        $user->shouldReceive('getAuthPassword')->andReturn('bar');
        $user->shouldReceive('getRememberToken')->andReturn('recaller');
        $user->shouldReceive('setRememberToken')->never();
        $provider->shouldReceive('updateRememberToken')->never();
        $events->shouldReceive('dispatch')->once()->with(m::type(Login::class));
        $events->shouldReceive('dispatch')->once()->with(m::type(Authenticated::class));
        $this->assertNull($guard->login($user, true));
    }

    public function testLoginMethodCreatesRememberTokenIfOneDoesntExist()
    {
        $guard = $this->getGuard();
        $cookies = $guard->getCookieJar();
        $session = $guard->getSession();
        $provider = $guard->getProvider();
        $events = $guard->getEventDispatcher();
        $foreverCookie = new Cookie($guard->getRecallerName(), 'foo');
        $cookies->shouldReceive('forever')->once()->andReturn($foreverCookie);
        $cookies->shouldReceive('queue')->once()->with($foreverCookie);
        $guard->getSession()->shouldReceive('put')->once()->with($guard->getName(), 'foo');
        $session->shouldReceive('migrate')->once();
        $user = m::mock(AuthenticatableInterface::class);
        $user->shouldReceive('getAuthIdentifier')->andReturn('foo');
        $user->shouldReceive('getAuthPassword')->andReturn('foo');
        $user->shouldReceive('getRememberToken')->andReturn(null);
        $user->shouldReceive('setRememberToken')->once();
        $provider->shouldReceive('updateRememberToken')->once();
        $events->shouldReceive('dispatch')->once()->with(m::type(Login::class));
        $events->shouldReceive('dispatch')->once()->with(m::type(Authenticated::class));
        $this->assertNull($guard->login($user, true));
    }

    public function testLoginUsingIdLogsInWithUser()
    {
        $guard = m::mock(SessionGuard::class, [$request, $session, $events, $cookies, $provider, $options] = $this->getMocks())->makePartial();

        $user = m::mock(AuthenticatableInterface::class);
        $guard->getProvider()->shouldReceive('retrieveById')->once()->with(10)->andReturn($user);
        $guard->shouldReceive('login')->once()->with($user, false);

        $this->assertSame($user, $guard->loginUsingId(10));
    }

    public function testLoginUsingIdFailure()
    {
        $guard = m::mock(SessionGuard::class, [$request, $session, $events, $cookies, $provider, $options] = $this->getMocks())->makePartial();

        $guard->getProvider()->shouldReceive('retrieveById')->once()->with(11)->andReturn(null);
        $guard->shouldNotReceive('login');

        $this->assertNull($guard->loginUsingId(11));
    }

    public function testOnceUsingIdSetsUser()
    {
        $guard = m::mock(SessionGuard::class, [$request, $session, $events, $cookies, $provider, $options] = $this->getMocks())->makePartial();

        $user = m::mock(AuthenticatableInterface::class);
        $guard->getProvider()->shouldReceive('retrieveById')->once()->with(10)->andReturn($user);
        $guard->shouldReceive('setUser')->once()->with($user);

        $this->assertSame($user, $guard->onceUsingId(10));
    }

    public function testOnceUsingIdFailure()
    {
        $guard = m::mock(SessionGuard::class, [$request, $session, $events, $cookies, $provider, $options] = $this->getMocks())->makePartial();

        $guard->getProvider()->shouldReceive('retrieveById')->once()->with(11)->andReturn(null);
        $guard->shouldNotReceive('setUser');

        $this->assertFalse($guard->onceUsingId(11));
    }

    public function testUserUsesRememberCookieIfItExists()
    {
        $guard = $this->getGuard();

        [$request, $session, $events, $cookies, $provider, $options] = $this->getMocks();

        $request = new \Hyperf\HttpMessage\Server\Request('GET', '/');
        $request = $request->withCookieParams([
            $guard->getRecallerName() => 'id|recaller|baz',
        ]);
        Context::set(ServerRequestInterface::class, $request);
        $request = new Request();

        $guard = new SessionGuard($request, $session, $events, $cookies, $provider, $options);
        $guard->getSession()->shouldReceive('get')->once()->with($guard->getName())->andReturn(null);
        $user = m::mock(AuthenticatableInterface::class);
        $guard->getProvider()->shouldReceive('retrieveByToken')->once()->with('id', 'recaller')->andReturn($user);
        $user->shouldReceive('getAuthIdentifier')->once()->andReturn('bar');
        $guard->getSession()->shouldReceive('put')->with($guard->getName(), 'bar')->once();
        $session->shouldReceive('migrate')->once();
        $guard->getEventDispatcher()->shouldReceive('dispatch')->once()->with(m::type(Login::class));
        $this->assertSame($user, $guard->user());
        $this->assertTrue($guard->viaRemember());
    }

    public function testLoginOnceSetsUser()
    {
        $guard = m::mock(SessionGuard::class, [$request, $session, $events, $cookies, $provider, $options] = $this->getMocks())->makePartial();
        $user = m::mock(AuthenticatableInterface::class);
        $guard->getProvider()->shouldReceive('retrieveByCredentials')->once()->with(['foo'])->andReturn($user);
        $guard->getProvider()->shouldReceive('validateCredentials')->once()->with($user, ['foo'])->andReturn(true);
        $guard->shouldReceive('setUser')->once()->with($user);
        $events->shouldReceive('dispatch')->once()->with(m::type(Attempting::class));
        $events->shouldReceive('dispatch')->once()->with(m::type(Validated::class));
        $this->assertTrue($guard->once(['foo']));
    }

    public function testLoginOnceFailure()
    {
        $guard = m::mock(SessionGuard::class, [$request, $session, $events, $cookies, $provider, $options] = $this->getMocks())->makePartial();
        $user = m::mock(AuthenticatableInterface::class);
        $guard->getProvider()->shouldReceive('retrieveByCredentials')->once()->with(['foo'])->andReturn($user);
        $guard->getProvider()->shouldReceive('validateCredentials')->once()->with($user, ['foo'])->andReturn(false);
        $events->shouldReceive('dispatch')->once()->with(m::type(Attempting::class));
        $this->assertFalse($guard->once(['foo']));
    }

    protected function getGuard()
    {
        return new SessionGuard(...$this->getMocks());
    }

    protected function getMocks()
    {
        Context::set(ServerRequestInterface::class, new \Hyperf\HttpMessage\Server\Request('GET', '/'));
        return [
            new Request(),
            m::mock(SessionInterface::class),
            m::mock(EventDispatcherInterface::class),
            m::mock(CookieJar::class),
            m::mock(UserProviderInterface::class),
            [
                'name' => 'foo',
            ],
        ];
    }

    protected function getCookieJar()
    {
        return new CookieJar();
//        return new CookieJar(Request::create('/foo', 'GET'), m::mock(Encrypter::class), ['domain' => 'foo.com', 'path' => '/', 'secure' => false, 'httpOnly' => false]);
    }
}
