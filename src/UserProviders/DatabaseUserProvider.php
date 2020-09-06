<?php

declare(strict_types=1);
/**
 * This file is part of hyperf-ext/auth.
 *
 * @link     https://github.com/hyperf-ext/auth
 * @contact  eric@zhu.email
 * @license  https://github.com/hyperf-ext/auth/blob/master/LICENSE
 */
namespace HyperfExt\Auth\UserProviders;

use Hyperf\Database\ConnectionInterface;
use Hyperf\Database\ConnectionResolverInterface;
use Hyperf\Utils\Contracts\Arrayable;
use Hyperf\Utils\Str;
use HyperfExt\Auth\Contracts\AuthenticatableInterface;
use HyperfExt\Auth\Contracts\UserProviderInterface;
use HyperfExt\Auth\GenericUser;
use HyperfExt\Hashing\Contract\DriverInterface as HasherInterface;
use HyperfExt\Hashing\Contract\HashInterface;

class DatabaseUserProvider implements UserProviderInterface
{
    /**
     * The active database connection.
     *
     * @var \Hyperf\Database\ConnectionInterface
     */
    protected $conn;

    /**
     * The hasher implementation.
     *
     * @var \HyperfExt\Hashing\Contract\HashInterface
     */
    protected $hasher;

    /**
     * The table containing the users.
     *
     * @var string
     */
    protected $table;

    /**
     * Create a new database user provider.
     */
    public function __construct(
        ConnectionResolverInterface $connectionResolver,
        HashInterface $hash,
        array $options
    ) {
        $this->conn = ($connection = $options['connection'] ?? null) instanceof ConnectionInterface
            ? $connection
            : $connectionResolver->connection($connection);
        $this->hasher = ($hasher = $options['hash_driver'] ?? null) instanceof HasherInterface
            ? $hasher
            : $hash->getDriver($hasher);
        $this->table = $options['table'] ?? null;
    }

    /**
     * Retrieve a user by their unique identifier.
     *
     * @param mixed $identifier
     */
    public function retrieveById($identifier): ?AuthenticatableInterface
    {
        $user = $this->conn->table($this->table)->find($identifier);

        return $this->getGenericUser($user);
    }

    /**
     * Retrieve a user by their unique identifier and "remember me" token.
     *
     * @param mixed $identifier
     */
    public function retrieveByToken($identifier, string $token): ?AuthenticatableInterface
    {
        $user = $this->getGenericUser(
            $this->conn->table($this->table)->find($identifier)
        );

        return $user && $user->getRememberToken() && hash_equals($user->getRememberToken(), $token)
            ? $user : null;
    }

    /**
     * Update the "remember me" token for the given user in storage.
     */
    public function updateRememberToken(AuthenticatableInterface $user, string $token): void
    {
        $this->conn->table($this->table)
            ->where($user->getAuthIdentifierName(), $user->getAuthIdentifier())
            ->update([$user->getRememberTokenName() => $token]);
    }

    /**
     * Retrieve a user by the given credentials.
     */
    public function retrieveByCredentials(array $credentials): ?AuthenticatableInterface
    {
        if (empty($credentials) ||
            (count($credentials) === 1 &&
                array_key_exists('password', $credentials))) {
            return null;
        }

        // First we will add each credential element to the query as a where clause.
        // Then we can execute the query and, if we found a user, return it in a
        // generic "user" object that will be utilized by the Guard instances.
        $query = $this->conn->table($this->table);

        foreach ($credentials as $key => $value) {
            if (Str::contains($key, 'password')) {
                continue;
            }

            if (is_array($value) || $value instanceof Arrayable) {
                $query->whereIn($key, $value);
            } else {
                $query->where($key, $value);
            }
        }

        // Now we are ready to execute the query to see if we have an user matching
        // the given credentials. If not, we will just return nulls and indicate
        // that there are no matching users for these given credential arrays.
        $user = $query->first();

        return $this->getGenericUser($user);
    }

    /**
     * Validate a user against the given credentials.
     */
    public function validateCredentials(AuthenticatableInterface $user, array $credentials): bool
    {
        return $this->hasher->check(
            $credentials['password'],
            $user->getAuthPassword()
        );
    }

    /**
     * Get the generic user.
     *
     * @param mixed $user
     */
    protected function getGenericUser($user): ?GenericUser
    {
        if (! is_null($user)) {
            return new GenericUser((array) $user);
        }
        return null;
    }
}
