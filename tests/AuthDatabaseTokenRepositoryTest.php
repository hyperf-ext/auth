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

use Carbon\Carbon;
use Hyperf\Database\ConnectionResolverInterface;
use Hyperf\Database\Query\Builder;
use Hyperf\DbConnection\Connection;
use HyperfExt\Auth\Contracts\CanResetPasswordInterface;
use HyperfExt\Auth\Passwords\DatabaseTokenRepository;
use HyperfExt\Hashing\Contract\DriverInterface;
use HyperfExt\Hashing\Contract\HashInterface;
use Mockery as m;
use PHPUnit\Framework\TestCase;

/**
 * @internal
 * @coversNothing
 */
class AuthDatabaseTokenRepositoryTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();

        Carbon::setTestNow(Carbon::now());
    }

    protected function tearDown(): void
    {
        parent::tearDown();

        m::close();
        Carbon::setTestNow(null);
    }

    public function testCreateInsertsNewRecordIntoTable()
    {
        $repo = $this->getRepo();
        $repo->getHasher()->shouldReceive('make')->once()->andReturn('hashed-token');
        $repo->getConnection()->shouldReceive('table')->times(2)->with('table')->andReturn($query = m::mock(Builder::class));
        $query->shouldReceive('where')->once()->with('email', 'email')->andReturn($query);
        $query->shouldReceive('delete')->once();
        $query->shouldReceive('insert')->once();
        $user = m::mock(CanResetPasswordInterface::class);
        $user->shouldReceive('getEmailForPasswordReset')->times(2)->andReturn('email');

        $results = $repo->create($user);

        $this->assertIsString($results);
        $this->assertGreaterThan(1, strlen($results));
    }

    public function testExistReturnsFalseIfNoRowFoundForUser()
    {
        $repo = $this->getRepo();
        $repo->getConnection()->shouldReceive('table')->once()->with('table')->andReturn($query = m::mock(Builder::class));
        $query->shouldReceive('where')->once()->with('email', 'email')->andReturn($query);
        $query->shouldReceive('first')->once()->andReturn(null);
        $user = m::mock(CanResetPasswordInterface::class);
        $user->shouldReceive('getEmailForPasswordReset')->once()->andReturn('email');

        $this->assertFalse($repo->exists($user, 'token'));
    }

    public function testExistReturnsFalseIfRecordIsExpired()
    {
        $repo = $this->getRepo();
        $repo->getConnection()->shouldReceive('table')->once()->with('table')->andReturn($query = m::mock(Builder::class));
        $query->shouldReceive('where')->once()->with('email', 'email')->andReturn($query);
        $date = Carbon::now()->subSeconds(300000)->toDateTimeString();
        $query->shouldReceive('first')->once()->andReturn((object) ['created_at' => $date, 'token' => 'hashed-token']);
        $user = m::mock(CanResetPasswordInterface::class);
        $user->shouldReceive('getEmailForPasswordReset')->once()->andReturn('email');

        $this->assertFalse($repo->exists($user, 'token'));
    }

    public function testExistReturnsTrueIfValidRecordExists()
    {
        $repo = $this->getRepo();
        $repo->getHasher()->shouldReceive('check')->once()->with('token', 'hashed-token')->andReturn(true);
        $repo->getConnection()->shouldReceive('table')->once()->with('table')->andReturn($query = m::mock(Builder::class));
        $query->shouldReceive('where')->once()->with('email', 'email')->andReturn($query);
        $date = Carbon::now()->subMinutes(10)->toDateTimeString();
        $query->shouldReceive('first')->once()->andReturn((object) ['created_at' => $date, 'token' => 'hashed-token']);
        $user = m::mock(CanResetPasswordInterface::class);
        $user->shouldReceive('getEmailForPasswordReset')->once()->andReturn('email');

        $this->assertTrue($repo->exists($user, 'token'));
    }

    public function testExistReturnsFalseIfInvalidToken()
    {
        $repo = $this->getRepo();
        $repo->getHasher()->shouldReceive('check')->once()->with('wrong-token', 'hashed-token')->andReturn(false);
        $repo->getConnection()->shouldReceive('table')->once()->with('table')->andReturn($query = m::mock(Builder::class));
        $query->shouldReceive('where')->once()->with('email', 'email')->andReturn($query);
        $date = Carbon::now()->subMinutes(10)->toDateTimeString();
        $query->shouldReceive('first')->once()->andReturn((object) ['created_at' => $date, 'token' => 'hashed-token']);
        $user = m::mock(CanResetPasswordInterface::class);
        $user->shouldReceive('getEmailForPasswordReset')->once()->andReturn('email');

        $this->assertFalse($repo->exists($user, 'wrong-token'));
    }

    public function testRecentlyCreatedReturnsFalseIfNoRowFoundForUser()
    {
        $repo = $this->getRepo();
        $repo->getConnection()->shouldReceive('table')->once()->with('table')->andReturn($query = m::mock(Builder::class));
        $query->shouldReceive('where')->once()->with('email', 'email')->andReturn($query);
        $query->shouldReceive('first')->once()->andReturn(null);
        $user = m::mock(CanResetPasswordInterface::class);
        $user->shouldReceive('getEmailForPasswordReset')->once()->andReturn('email');

        $this->assertFalse($repo->recentlyCreatedToken($user));
    }

    public function testRecentlyCreatedReturnsTrueIfRecordIsRecentlyCreated()
    {
        $repo = $this->getRepo();
        $repo->getConnection()->shouldReceive('table')->once()->with('table')->andReturn($query = m::mock(Builder::class));
        $query->shouldReceive('where')->once()->with('email', 'email')->andReturn($query);
        $date = Carbon::now()->subSeconds(59)->toDateTimeString();
        $query->shouldReceive('first')->once()->andReturn((object) ['created_at' => $date, 'token' => 'hashed-token']);
        $user = m::mock(CanResetPasswordInterface::class);
        $user->shouldReceive('getEmailForPasswordReset')->once()->andReturn('email');

        $this->assertTrue($repo->recentlyCreatedToken($user));
    }

    public function testRecentlyCreatedReturnsFalseIfValidRecordExists()
    {
        $repo = $this->getRepo();
        $repo->getConnection()->shouldReceive('table')->once()->with('table')->andReturn($query = m::mock(Builder::class));
        $query->shouldReceive('where')->once()->with('email', 'email')->andReturn($query);
        $date = Carbon::now()->subSeconds(61)->toDateTimeString();
        $query->shouldReceive('first')->once()->andReturn((object) ['created_at' => $date, 'token' => 'hashed-token']);
        $user = m::mock(CanResetPasswordInterface::class);
        $user->shouldReceive('getEmailForPasswordReset')->once()->andReturn('email');

        $this->assertFalse($repo->recentlyCreatedToken($user));
    }

    public function testDeleteMethodDeletesByToken()
    {
        $repo = $this->getRepo();
        $repo->getConnection()->shouldReceive('table')->once()->with('table')->andReturn($query = m::mock(Builder::class));
        $query->shouldReceive('where')->once()->with('email', 'email')->andReturn($query);
        $query->shouldReceive('delete')->once();
        $user = m::mock(CanResetPasswordInterface::class);
        $user->shouldReceive('getEmailForPasswordReset')->once()->andReturn('email');

        $this->assertNull($repo->delete($user));
    }

    public function testDeleteExpiredMethodDeletesExpiredTokens()
    {
        $repo = $this->getRepo();
        $repo->getConnection()->shouldReceive('table')->once()->with('table')->andReturn($query = m::mock(Builder::class));
        $query->shouldReceive('where')->once()->with('created_at', '<', m::any())->andReturn($query);
        $query->shouldReceive('delete')->once();

        $this->assertNull($repo->deleteExpired());
    }

    protected function getRepo()
    {
        return new DatabaseTokenRepository(
            m::mock(ConnectionResolverInterface::class),
            m::mock(HashInterface::class),
            [
                'provider' => 'users',
                'connection' => m::mock(Connection::class),
                'table' => 'table',
                'expire' => 3600,
                'throttle' => 60,
                'hash_driver' => m::mock(DriverInterface::class),
            ]
        );
    }
}
