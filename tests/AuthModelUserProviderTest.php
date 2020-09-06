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

use Hyperf\Database\Model\Model;
use HyperfExt\Auth\Contracts\AuthenticatableInterface;
use HyperfExt\Auth\UserProviders\ModelUserProvider;
use HyperfExt\Hashing\Contract\DriverInterface;
use HyperfExt\Hashing\Contract\HashInterface;
use Mockery as m;
use PHPUnit\Framework\TestCase;

/**
 * @internal
 * @coversNothing
 */
class AuthModelUserProviderTest extends TestCase
{
    protected function tearDown(): void
    {
        m::close();
    }

    public function testRetrieveByIDReturnsUser()
    {
        $mockUser = m::mock(AuthenticatableInterface::class);

        $provider = $this->getProviderMock();
        $mock = m::mock(Model::class);
        $user = m::mock(AuthenticatableInterface::class);
        $mock->shouldReceive('newQuery')->once()->andReturn($mock);
        $mock->shouldReceive('getAuthIdentifierName')->once()->andReturn('id');
        $mock->shouldReceive('where')->once()->with('id', 1)->andReturn($mock);
        $mock->shouldReceive('first')->once()->andReturn($user);
        $provider->expects($this->once())->method('createModel')->willReturn($mock);
        $user = $provider->retrieveById(1);

        $this->assertEquals($mockUser, $user);
    }

    public function testRetrieveByTokenReturnsUser()
    {
        $mockUser = m::mock(AuthenticatableInterface::class);
        $mockUser->shouldReceive('getRememberToken')->once()->andReturn('a');

        $provider = $this->getProviderMock();
        $mock = m::mock(Model::class);
        $mock->shouldReceive('newQuery')->once()->andReturn($mock);
        $mock->shouldReceive('getAuthIdentifierName')->once()->andReturn('id');
        $mock->shouldReceive('where')->once()->with('id', 1)->andReturn($mock);
        $mock->shouldReceive('first')->once()->andReturn($mockUser);
        $provider->expects($this->once())->method('createModel')->willReturn($mock);
        $user = $provider->retrieveByToken(1, 'a');

        $this->assertEquals($mockUser, $user);
    }

    public function testRetrieveTokenWithBadIdentifierReturnsNull()
    {
        $provider = $this->getProviderMock();
        $mock = m::mock(Model::class);
        $mock->shouldReceive('newQuery')->once()->andReturn($mock);
        $mock->shouldReceive('getAuthIdentifierName')->once()->andReturn('id');
        $mock->shouldReceive('where')->once()->with('id', 1)->andReturn($mock);
        $mock->shouldReceive('first')->once()->andReturn(null);
        $provider->expects($this->once())->method('createModel')->willReturn($mock);
        $user = $provider->retrieveByToken(1, 'a');

        $this->assertNull($user);
    }

    public function testRetrievingWithOnlyPasswordCredentialReturnsNull()
    {
        $provider = $this->getProviderMock();
        $user = $provider->retrieveByCredentials(['api_password' => 'foo']);

        $this->assertNull($user);
    }

    public function testRetrieveByBadTokenReturnsNull()
    {
        $mockUser = m::mock(AuthenticatableInterface::class);
        $mockUser->shouldReceive('getRememberToken')->once()->andReturn(null);

        $provider = $this->getProviderMock();
        $mock = m::mock(Model::class);
        $mock->shouldReceive('newQuery')->once()->andReturn($mock);
        $mock->shouldReceive('getAuthIdentifierName')->once()->andReturn('id');
        $mock->shouldReceive('where')->once()->with('id', 1)->andReturn($mock);
        $mock->shouldReceive('first')->once()->andReturn($mockUser);
        $provider->expects($this->once())->method('createModel')->willReturn($mock);
        $user = $provider->retrieveByToken(1, 'a');

        $this->assertNull($user);
    }

    public function testRetrieveByCredentialsReturnsUser()
    {
        $mockUser = m::mock(AuthenticatableInterface::class);
        $provider = $this->getProviderMock();
        $mock = m::mock(Model::class);
        $mock->shouldReceive('newQuery')->once()->andReturn($mock);
        $mock->shouldReceive('where')->once()->with('username', 'dayle');
        $mock->shouldReceive('whereIn')->once()->with('group', ['one', 'two']);
        $mock->shouldReceive('first')->once()->andReturn($mockUser);
        $provider->expects($this->once())->method('createModel')->willReturn($mock);
        $user = $provider->retrieveByCredentials(['username' => 'dayle', 'password' => 'foo', 'group' => ['one', 'two']]);

        $this->assertSame($mockUser, $user);
    }

    public function testCredentialValidation()
    {
        $hasher = m::mock(DriverInterface::class);
        $hasher->shouldReceive('check')->once()->with('plain', 'hash')->andReturn(true);
        $provider = new ModelUserProvider(
            m::mock(HashInterface::class),
            [
                'model' => EloquentProviderUserStub::class,
                'hash_driver' => $hasher,
            ]
        );
        $user = m::mock(AuthenticatableInterface::class);
        $user->shouldReceive('getAuthPassword')->once()->andReturn('hash');
        $result = $provider->validateCredentials($user, ['password' => 'plain']);

        $this->assertTrue($result);
    }

    public function testModelsCanBeCreated()
    {
        $hasher = m::mock(DriverInterface::class);
        $provider = new ModelUserProvider(
            m::mock(HashInterface::class),
            [
                'model' => EloquentProviderUserStub::class,
                'hash_driver' => $hasher,
            ]
        );
        $model = $provider->createModel();

        $this->assertInstanceOf(EloquentProviderUserStub::class, $model);
    }

    protected function getProviderMock()
    {
        $hasher = m::mock(DriverInterface::class);

        return $this->getMockBuilder(ModelUserProvider::class)
            ->setMethods(['createModel'])
            ->setConstructorArgs([
                m::mock(HashInterface::class),
                [
                    'model' => EloquentProviderUserStub::class,
                    'hash_driver' => $hasher,
                ],
            ])
            ->getMock();
    }
}

class EloquentProviderUserStub
{
}
