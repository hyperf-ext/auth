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

use Hyperf\Utils\Contracts\Arrayable;
use Hyperf\Utils\Str;
use HyperfExt\Auth\Contracts\AuthenticatableInterface;
use HyperfExt\Auth\Contracts\UserProviderInterface;
use HyperfExt\Hashing\Contract\DriverInterface as HasherInterface;
use HyperfExt\Hashing\Contract\HashInterface;

class ModelUserProvider implements UserProviderInterface
{
    /**
     * The hasher implementation.
     *
     * @var \HyperfExt\Hashing\Contract\HashInterface
     */
    protected $hasher;

    /**
     * The Eloquent user model.
     *
     * @var string
     */
    protected $model;

    /**
     * Create a new database user provider.
     */
    public function __construct(HashInterface $hash, array $options)
    {
        $this->model = $options['model'] ?? null;
        $this->hasher = ($hasher = $options['hash_driver'] ?? null) instanceof HasherInterface
            ? $hasher
            : $hash->getDriver($hasher);
    }

    /**
     * Retrieve a user by their unique identifier.
     *
     * @param mixed $identifier
     *
     * @return null|\Hyperf\Database\Model\Model|\HyperfExt\Auth\Contracts\AuthenticatableInterface
     */
    public function retrieveById($identifier): ?AuthenticatableInterface
    {
        $model = $this->createModel();

        return $this->newModelQuery($model)
            ->where($model->getAuthIdentifierName(), $identifier)
            ->first();
    }

    /**
     * Retrieve a user by their unique identifier and "remember me" token.
     *
     * @param mixed $identifier
     *
     * @return null|\Hyperf\Database\Model\Model|\HyperfExt\Auth\Contracts\AuthenticatableInterface
     */
    public function retrieveByToken($identifier, string $token): ?AuthenticatableInterface
    {
        $model = $this->createModel();

        $retrievedModel = $this->newModelQuery($model)->where(
            $model->getAuthIdentifierName(),
            $identifier
        )->first();

        if (! $retrievedModel) {
            return null;
        }

        $rememberToken = $retrievedModel->getRememberToken();

        return $rememberToken && hash_equals($rememberToken, $token)
            ? $retrievedModel : null;
    }

    /**
     * Update the "remember me" token for the given user in storage.
     *
     * @param \Hyperf\Database\Model\Model|\HyperfExt\Auth\Contracts\AuthenticatableInterface $user
     */
    public function updateRememberToken(AuthenticatableInterface $user, string $token): void
    {
        $user->setRememberToken($token);

        $timestamps = $user->timestamps;

        $user->timestamps = false;

        $user->save();

        $user->timestamps = $timestamps;
    }

    /**
     * Retrieve a user by the given credentials.
     *
     * @return null|\Hyperf\Database\Model\Model|\HyperfExt\Auth\Contracts\AuthenticatableInterface
     */
    public function retrieveByCredentials(array $credentials): ?AuthenticatableInterface
    {
        if (empty($credentials) ||
            (count($credentials) === 1 &&
                Str::contains($this->firstCredentialKey($credentials), 'password'))) {
            return null;
        }

        // First we will add each credential element to the query as a where clause.
        // Then we can execute the query and, if we found a user, return it in a
        // Eloquent User "model" that will be utilized by the Guard instances.
        $query = $this->newModelQuery();

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

        return $query->first();
    }

    /**
     * Validate a user against the given credentials.
     */
    public function validateCredentials(AuthenticatableInterface $user, array $credentials): bool
    {
        $plain = $credentials['password'];

        return $this->hasher->check($plain, $user->getAuthPassword());
    }

    /**
     * Create a new instance of the model.
     *
     * @return null|\Hyperf\Database\Model\Model|\HyperfExt\Auth\Contracts\AuthenticatableInterface
     */
    public function createModel()
    {
        $class = '\\' . ltrim($this->model, '\\');

        return new $class();
    }

    /**
     * Gets the hasher implementation.
     */
    public function getHashInterface(): HashInterface
    {
        return $this->hasher;
    }

    /**
     * Sets the hasher implementation.
     *
     * @return $this
     */
    public function setHashInterface(HashInterface $hasher)
    {
        $this->hasher = $hasher;

        return $this;
    }

    /**
     * Gets the name of the Eloquent user model.
     */
    public function getModel(): string
    {
        return $this->model;
    }

    /**
     * Sets the name of the Eloquent user model.
     *
     * @return $this
     */
    public function setModel(string $model)
    {
        $this->model = $model;

        return $this;
    }

    /**
     * Get the first key from the credential array.
     */
    protected function firstCredentialKey(array $credentials): ?string
    {
        foreach ($credentials as $key => $value) {
            return $key;
        }
        return null;
    }

    /**
     * Get a new query builder for the model instance.
     *
     * @param null|\Hyperf\Database\Model\Model|\HyperfExt\Auth\Contracts\AuthenticatableInterface $model
     * @return \Hyperf\Database\Model\Builder
     */
    protected function newModelQuery($model = null)
    {
        return is_null($model)
            ? $this->createModel()->newQuery()
            : $model->newQuery();
    }
}
