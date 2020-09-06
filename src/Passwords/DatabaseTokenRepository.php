<?php

declare(strict_types=1);
/**
 * This file is part of hyperf-ext/auth.
 *
 * @link     https://github.com/hyperf-ext/auth
 * @contact  eric@zhu.email
 * @license  https://github.com/hyperf-ext/auth/blob/master/LICENSE
 */
namespace HyperfExt\Auth\Passwords;

use Carbon\Carbon;
use Hyperf\Database\ConnectionInterface;
use Hyperf\Database\ConnectionResolverInterface;
use Hyperf\Database\Query\Builder;
use Hyperf\DbConnection\Connection;
use HyperfExt\Auth\Contracts\CanResetPasswordInterface;
use HyperfExt\Auth\Contracts\TokenRepositoryInterface;
use HyperfExt\Hashing\Contract\DriverInterface as HasherInterface;
use HyperfExt\Hashing\Contract\HashInterface;

class DatabaseTokenRepository implements TokenRepositoryInterface
{
    /**
     * The database connection instance.
     *
     * @var \Hyperf\DbConnection\Connection
     */
    protected $connection;

    /**
     * The Hasher implementation.
     *
     * @var \HyperfExt\Hashing\Contract\DriverInterface
     */
    protected $hasher;

    /**
     * The token database table.
     *
     * @var string
     */
    protected $table;

    /**
     * The number of seconds a token should last.
     *
     * @var int
     */
    protected $expires;

    /**
     * Minimum number of seconds before re-redefining the token.
     *
     * @var int
     */
    protected $throttle;

    /**
     * Create a new token repository instance.
     */
    public function __construct(
        ConnectionResolverInterface $connectionResolver,
        HashInterface $hash,
        array $options = []
    ) {
        $this->connection = ($connection = $options['connection'] ?? null) instanceof ConnectionInterface
            ? $connection
            : $connectionResolver->connection($connection);
        $this->hasher = ($hasher = $options['hash_driver'] ?? null) instanceof HasherInterface
            ? $hasher
            : $hash->getDriver($hasher);
        $this->table = $options['table'];
        $this->expires = $options['expires'] ?? 3600;
        $this->throttle = $options['throttle'] ?? 60;
    }

    /**
     * Create a new token record.
     */
    public function create(CanResetPasswordInterface $user): string
    {
        $email = $user->getEmailForPasswordReset();

        $this->deleteExisting($user);

        // We will create a new, random token for the user so that we can e-mail them
        // a safe link to the password reset form. Then we will insert a record in
        // the database so that we can verify the token within the actual reset.
        $token = $this->createNewToken();

        $this->getTable()->insert($this->getPayload($email, $token));

        return $token;
    }

    /**
     * Determine if a token record exists and is valid.
     */
    public function exists(CanResetPasswordInterface $user, string $token): bool
    {
        $record = (array) $this->getTable()->where(
            'email',
            $user->getEmailForPasswordReset()
        )->first();

        return $record &&
               ! $this->tokenExpired($record['created_at']) &&
                 $this->hasher->check($token, $record['token']);
    }

    /**
     * Determine if the given user recently created a password reset token.
     */
    public function recentlyCreatedToken(CanResetPasswordInterface $user): bool
    {
        $record = (array) $this->getTable()->where(
            'email',
            $user->getEmailForPasswordReset()
        )->first();

        return $record && $this->tokenRecentlyCreated($record['created_at']);
    }

    /**
     * Delete a token record by user.
     */
    public function delete(CanResetPasswordInterface $user): void
    {
        $this->deleteExisting($user);
    }

    /**
     * Delete expired tokens.
     */
    public function deleteExpired(): void
    {
        $expiredAt = Carbon::now()->subSeconds($this->expires);

        $this->getTable()->where('created_at', '<', $expiredAt)->delete();
    }

    /**
     * Create a new token for the user.
     */
    public function createNewToken(): string
    {
        return hash('sha256', random_bytes(512));
    }

    /**
     * Get the database connection instance.
     */
    public function getConnection(): Connection
    {
        return $this->connection;
    }

    /**
     * Get the hasher instance.
     */
    public function getHasher(): HasherInterface
    {
        return $this->hasher;
    }

    /**
     * Delete all existing reset tokens from the database.
     */
    protected function deleteExisting(CanResetPasswordInterface $user): ?int
    {
        return $this->getTable()->where('email', $user->getEmailForPasswordReset())->delete();
    }

    /**
     * Build the record payload for the table.
     */
    protected function getPayload(string $email, string $token): array
    {
        return ['email' => $email, 'token' => $this->hasher->make($token), 'created_at' => new Carbon()];
    }

    /**
     * Determine if the token has expired.
     */
    protected function tokenExpired(string $createdAt): bool
    {
        return Carbon::parse($createdAt)->addSeconds($this->expires)->isPast();
    }

    /**
     * Determine if the token was recently created.
     */
    protected function tokenRecentlyCreated(string $createdAt): bool
    {
        if ($this->throttle <= 0) {
            return false;
        }

        return Carbon::parse($createdAt)->addSeconds(
            $this->throttle
        )->isFuture();
    }

    /**
     * Begin a new database query against the table.
     */
    protected function getTable(): Builder
    {
        return $this->connection->table($this->table);
    }
}
