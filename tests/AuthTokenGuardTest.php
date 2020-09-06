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

use Hyperf\HttpServer\Request;
use Hyperf\Utils\Context;
use HyperfExt\Auth\Contracts\UserProviderInterface;
use HyperfExt\Auth\Guards\TokenGuard;
use Mockery as m;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ServerRequestInterface;

/**
 * @internal
 * @coversNothing
 */
class AuthTokenGuardTest extends TestCase
{
    protected function tearDown(): void
    {
        m::close();
    }

    public function testUserCanBeRetrievedByQueryStringVariable()
    {
        $provider = m::mock(UserProviderInterface::class);
        $user = new AuthTokenGuardTestUser();
        $user->id = 1;
        $provider->shouldReceive('retrieveByCredentials')->once()->with(['api_token' => 'foo'])->andReturn($user);
        $request = $this->createRequest(['api_token' => 'foo']);

        $guard = new TokenGuard($request, $provider);

        $user = $guard->user();

        $this->assertEquals(1, $user->id);
        $this->assertTrue($guard->check());
        $this->assertFalse($guard->guest());
        $this->assertEquals(1, $guard->id());
    }

    public function testTokenCanBeHashed()
    {
        $provider = m::mock(UserProviderInterface::class);
        $user = new AuthTokenGuardTestUser();
        $user->id = 1;
        $provider->shouldReceive('retrieveByCredentials')->once()->with(['api_token' => hash('sha256', 'foo')])->andReturn($user);
        $request = $this->createRequest(['api_token' => 'foo']);

        $guard = new TokenGuard($request, $provider, [
            'input_key' => 'api_token',
            'storage_key' => 'api_token',
            'hash' => true,
        ]);

        $user = $guard->user();

        $this->assertEquals(1, $user->id);
        $this->assertTrue($guard->check());
        $this->assertFalse($guard->guest());
        $this->assertEquals(1, $guard->id());
    }

    public function testUserCanBeRetrievedByAuthHeaders()
    {
        $provider = m::mock(UserProviderInterface::class);
        $provider->shouldReceive('retrieveByCredentials')->once()->with(['api_token' => 'foo'])->andReturn(new AuthTokenGuardTestUser());
        $request = $this->createRequest([], ['Authorization' => 'Basic ' . base64_encode('foo:foo')]);

        $guard = new TokenGuard($request, $provider);

        $user = $guard->user();

        $this->assertEquals(1, $user->id);
    }

    public function testUserCanBeRetrievedByBearerToken()
    {
        $provider = m::mock(UserProviderInterface::class);
        $provider->shouldReceive('retrieveByCredentials')->once()->with(['api_token' => 'foo'])->andReturn(new AuthTokenGuardTestUser());
        $request = $this->createRequest([], ['Authorization' => 'Bearer foo']);

        $guard = new TokenGuard($request, $provider);

        $user = $guard->user();

        $this->assertEquals(1, $user->id);
    }

    public function testValidateCanDetermineIfCredentialsAreValid()
    {
        $provider = m::mock(UserProviderInterface::class);
        $user = new AuthTokenGuardTestUser();
        $user->id = 1;
        $provider->shouldReceive('retrieveByCredentials')->once()->with(['api_token' => 'foo'])->andReturn($user);
        $request = $this->createRequest(['api_token' => 'foo']);

        $guard = new TokenGuard($request, $provider);

        $this->assertTrue($guard->validate(['api_token' => 'foo']));
    }

    public function testValidateCanDetermineIfCredentialsAreInvalid()
    {
        $provider = m::mock(UserProviderInterface::class);
        $provider->shouldReceive('retrieveByCredentials')->once()->with(['api_token' => 'foo'])->andReturn(null);
        $request = $this->createRequest(['api_token' => 'foo']);

        $guard = new TokenGuard($request, $provider);

        $this->assertFalse($guard->validate(['api_token' => 'foo']));
    }

    public function testValidateIfApiTokenIsEmpty()
    {
        $provider = m::mock(UserProviderInterface::class);
        $request = $this->createRequest(['api_token' => 'foo']);

        $guard = new TokenGuard($request, $provider);

        $this->assertFalse($guard->validate(['api_token' => '']));
    }

    public function testItAllowsToPassCustomRequestInSetterAndUseItForValidation()
    {
        $provider = m::mock(UserProviderInterface::class);
        $user = new AuthTokenGuardTestUser();
        $user->id = 1;
        $provider->shouldReceive('retrieveByCredentials')->once()->with(['api_token' => 'custom'])->andReturn($user);
        $request = $this->createRequest(['api_token' => 'foo']);

        $guard = new TokenGuard($request, $provider);
        $guard->setRequest($this->createRequest(['api_token' => 'custom']));

        $user = $guard->user();

        $this->assertEquals(1, $user->id);
    }

    public function testUserCanBeRetrievedByBearerTokenWithCustomKey()
    {
        $provider = m::mock(UserProviderInterface::class);
        $provider->shouldReceive('retrieveByCredentials')->once()->with(['custom_token_field' => 'foo'])->andReturn(new AuthTokenGuardTestUser());
        $request = $this->createRequest([], ['Authorization' => 'Bearer foo']);

        $guard = new TokenGuard($request, $provider, [
            'input_key' => 'custom_token_field',
            'storage_key' => 'custom_token_field',
        ]);

        $user = $guard->user();

        $this->assertEquals(1, $user->id);
    }

    public function testUserCanBeRetrievedByQueryStringVariableWithCustomKey()
    {
        $provider = m::mock(UserProviderInterface::class);
        $user = new AuthTokenGuardTestUser();
        $user->id = 1;
        $provider->shouldReceive('retrieveByCredentials')->once()->with(['custom_token_field' => 'foo'])->andReturn($user);
        $request = $this->createRequest(['custom_token_field' => 'foo']);

        $guard = new TokenGuard($request, $provider, [
            'input_key' => 'custom_token_field',
            'storage_key' => 'custom_token_field',
        ]);

        $user = $guard->user();

        $this->assertEquals(1, $user->id);
        $this->assertTrue($guard->check());
        $this->assertFalse($guard->guest());
        $this->assertEquals(1, $guard->id());
    }

    public function testUserCanBeRetrievedByAuthHeadersWithCustomField()
    {
        $provider = m::mock(UserProviderInterface::class);
        $provider->shouldReceive('retrieveByCredentials')->once()->with(['custom_token_field' => 'foo'])->andReturn(new AuthTokenGuardTestUser());
        $request = $this->createRequest([], ['Authorization' => 'Basic ' . base64_encode('foo:foo')]);

        $guard = new TokenGuard($request, $provider, [
            'input_key' => 'custom_token_field',
            'storage_key' => 'custom_token_field',
        ]);

        $user = $guard->user();

        $this->assertEquals(1, $user->id);
    }

    public function testValidateCanDetermineIfCredentialsAreValidWithCustomKey()
    {
        $provider = m::mock(UserProviderInterface::class);
        $user = new AuthTokenGuardTestUser();
        $user->id = 1;
        $provider->shouldReceive('retrieveByCredentials')->once()->with(['custom_token_field' => 'foo'])->andReturn($user);
        $request = $this->createRequest(['custom_token_field' => 'foo']);

        $guard = new TokenGuard($request, $provider, [
            'input_key' => 'custom_token_field',
            'storage_key' => 'custom_token_field',
        ]);

        $this->assertTrue($guard->validate(['custom_token_field' => 'foo']));
    }

    public function testValidateCanDetermineIfCredentialsAreInvalidWithCustomKey()
    {
        $provider = m::mock(UserProviderInterface::class);
        $provider->shouldReceive('retrieveByCredentials')->once()->with(['custom_token_field' => 'foo'])->andReturn(null);
        $request = $this->createRequest(['custom_token_field' => 'foo']);

        $guard = new TokenGuard($request, $provider, [
            'input_key' => 'custom_token_field',
            'storage_key' => 'custom_token_field',
        ]);

        $this->assertFalse($guard->validate(['custom_token_field' => 'foo']));
    }

    public function testValidateIfApiTokenIsEmptyWithCustomKey()
    {
        $provider = m::mock(UserProviderInterface::class);
        $request = $this->createRequest(['custom_token_field' => '']);

        $guard = new TokenGuard($request, $provider, [
            'input_key' => 'custom_token_field',
            'storage_key' => 'custom_token_field',
        ]);

        $this->assertFalse($guard->validate(['custom_token_field' => '']));
    }

    protected function createRequest(array $params = [], array $headers = [])
    {
        $request = new \Hyperf\HttpMessage\Server\Request('GET', '/');
        Context::set(ServerRequestInterface::class, $request->withQueryParams($params)->withHeaders($headers));
        return new Request();
    }
}

class AuthTokenGuardTestUser extends User
{
    public $id;

    public function getAuthIdentifier()
    {
        return $this->id;
    }
}
