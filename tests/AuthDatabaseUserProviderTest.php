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

use Hyperf\Database\ConnectionInterface;
use Hyperf\Database\ConnectionResolverInterface;
use Hyperf\Database\Query\Builder;
use HyperfExt\Auth\Contracts\AuthenticatableInterface;
use HyperfExt\Auth\GenericUser;
use HyperfExt\Auth\UserProviders\DatabaseUserProvider;
use HyperfExt\Hashing\Contract\DriverInterface;
use HyperfExt\Hashing\Contract\HashInterface;
use Mockery as m;
use PHPUnit\Framework\TestCase;
use stdClass;

/**
 * @internal
 * @coversNothing
 */
class AuthDatabaseUserProviderTest extends TestCase
{
    protected function tearDown(): void
    {
        m::close();
    }

    public function testRetrieveByIDReturnsUserWhenUserIsFound()
    {
        $conn = m::mock(ConnectionInterface::class);
        $conn->shouldReceive('table')->once()->with('foo')->andReturn($query = m::mock(Builder::class));
        $query->shouldReceive('find')->once()->with(1)->andReturn(['id' => 1, 'name' => 'Dayle']);
        $hasher = m::mock(DriverInterface::class);
        $provider = new DatabaseUserProvider(
            m::mock(ConnectionResolverInterface::class),
            m::mock(HashInterface::class),
            [
                'connection' => $conn,
                'table' => 'foo',
                'hash_driver' => $hasher,
            ]
        );
        $user = $provider->retrieveById(1);

        $this->assertInstanceOf(GenericUser::class, $user);
        $this->assertEquals(1, $user->getAuthIdentifier());
        $this->assertSame('Dayle', $user->name);
    }

    public function testRetrieveByIDReturnsNullWhenUserIsNotFound()
    {
        $conn = m::mock(ConnectionInterface::class);
        $conn->shouldReceive('table')->once()->with('foo')->andReturn($query = m::mock(Builder::class));
        $query->shouldReceive('find')->once()->with(1)->andReturn(null);
        $hasher = m::mock(DriverInterface::class);
        $provider = new DatabaseUserProvider(
            m::mock(ConnectionResolverInterface::class),
            m::mock(HashInterface::class),
            [
                'connection' => $conn,
                'table' => 'foo',
                'hash_driver' => $hasher,
            ]
        );
        $user = $provider->retrieveById(1);

        $this->assertNull($user);
    }

    public function testRetrieveByTokenReturnsUser()
    {
        $mockUser = new stdClass();
        $mockUser->remember_token = 'a';

        $conn = m::mock(ConnectionInterface::class);
        $conn->shouldReceive('table')->once()->with('foo')->andReturn($query = m::mock(Builder::class));
        $query->shouldReceive('find')->once()->with(1)->andReturn($mockUser);
        $hasher = m::mock(DriverInterface::class);
        $provider = new DatabaseUserProvider(
            m::mock(ConnectionResolverInterface::class),
            m::mock(HashInterface::class),
            [
                'connection' => $conn,
                'table' => 'foo',
                'hash_driver' => $hasher,
            ]
        );
        $user = $provider->retrieveByToken(1, 'a');

        $this->assertEquals(new GenericUser((array) $mockUser), $user);
    }

    public function testRetrieveTokenWithBadIdentifierReturnsNull()
    {
        $conn = m::mock(ConnectionInterface::class);
        $conn->shouldReceive('table')->once()->with('foo')->andReturn($query = m::mock(Builder::class));
        $query->shouldReceive('find')->once()->with(1)->andReturn(null);
        $hasher = m::mock(DriverInterface::class);
        $provider = new DatabaseUserProvider(
            m::mock(ConnectionResolverInterface::class),
            m::mock(HashInterface::class),
            [
                'connection' => $conn,
                'table' => 'foo',
                'hash_driver' => $hasher,
            ]
        );
        $user = $provider->retrieveByToken(1, 'a');

        $this->assertNull($user);
    }

    public function testRetrieveByBadTokenReturnsNull()
    {
        $mockUser = new stdClass();
        $mockUser->remember_token = null;

        $conn = m::mock(ConnectionInterface::class);
        $conn->shouldReceive('table')->once()->with('foo')->andReturn($query = m::mock(Builder::class));
        $query->shouldReceive('find')->once()->with(1)->andReturn($mockUser);
        $hasher = m::mock(DriverInterface::class);
        $provider = new DatabaseUserProvider(
            m::mock(ConnectionResolverInterface::class),
            m::mock(HashInterface::class),
            [
                'connection' => $conn,
                'table' => 'foo',
                'hash_driver' => $hasher,
            ]
        );
        $user = $provider->retrieveByToken(1, 'a');

        $this->assertNull($user);
    }

    public function testRetrieveByCredentialsReturnsUserWhenUserIsFound()
    {
        $conn = m::mock(ConnectionInterface::class);
        $conn->shouldReceive('table')->once()->with('foo')->andReturn($query = m::mock(Builder::class));
        $query->shouldReceive('where')->once()->with('username', 'dayle');
        $query->shouldReceive('whereIn')->once()->with('group', ['one', 'two']);
        $query->shouldReceive('first')->once()->andReturn(['id' => 1, 'name' => 'taylor']);
        $hasher = m::mock(DriverInterface::class);
        $provider = new DatabaseUserProvider(
            m::mock(ConnectionResolverInterface::class),
            m::mock(HashInterface::class),
            [
                'connection' => $conn,
                'table' => 'foo',
                'hash_driver' => $hasher,
            ]
        );
        $user = $provider->retrieveByCredentials(['username' => 'dayle', 'password' => 'foo', 'group' => ['one', 'two']]);

        $this->assertInstanceOf(GenericUser::class, $user);
        $this->assertEquals(1, $user->getAuthIdentifier());
        $this->assertSame('taylor', $user->name);
    }

    public function testRetrieveByCredentialsReturnsNullWhenUserIsFound()
    {
        $conn = m::mock(ConnectionInterface::class);
        $conn->shouldReceive('table')->once()->with('foo')->andReturn($query = m::mock(Builder::class));
        $query->shouldReceive('where')->once()->with('username', 'dayle');
        $query->shouldReceive('first')->once()->andReturn(null);
        $hasher = m::mock(DriverInterface::class);
        $provider = new DatabaseUserProvider(
            m::mock(ConnectionResolverInterface::class),
            m::mock(HashInterface::class),
            [
                'connection' => $conn,
                'table' => 'foo',
                'hash_driver' => $hasher,
            ]
        );
        $user = $provider->retrieveByCredentials(['username' => 'dayle']);

        $this->assertNull($user);
    }

    public function testCredentialValidation()
    {
        $conn = m::mock(ConnectionInterface::class);
        $hasher = m::mock(DriverInterface::class);
        $hasher->shouldReceive('check')->once()->with('plain', 'hash')->andReturn(true);
        $provider = new DatabaseUserProvider(
            m::mock(ConnectionResolverInterface::class),
            m::mock(HashInterface::class),
            [
                'connection' => $conn,
                'table' => 'foo',
                'hash_driver' => $hasher,
            ]
        );
        $user = m::mock(AuthenticatableInterface::class);
        $user->shouldReceive('getAuthPassword')->once()->andReturn('hash');
        $result = $provider->validateCredentials($user, ['password' => 'plain']);

        $this->assertTrue($result);
    }
}
