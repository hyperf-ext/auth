<?php

declare(strict_types=1);
/**
 * This file is part of hyperf-ext/auth.
 *
 * @link     https://github.com/hyperf-ext/auth
 * @contact  eric@zhu.email
 * @license  https://github.com/hyperf-ext/auth/blob/master/LICENSE
 */
namespace HyperfExt\Auth\Commands;

class PolicyOption
{
    /**
     * @var string
     */
    protected $path;

    /**
     * @var null|string
     */
    protected $model;

    /**
     * @var null|string
     */
    protected $guard;

    public function getPath(): string
    {
        return $this->path;
    }

    public function setPath(string $path): self
    {
        $this->path = $path;
        return $this;
    }

    public function getModel(): ?string
    {
        return $this->model;
    }

    public function setModel(?string $model): self
    {
        $this->model = $model;
        return $this;
    }

    public function getGuard(): ?string
    {
        return $this->guard;
    }

    public function setGuard(?string $guard): self
    {
        $this->guard = $guard;
        return $this;
    }
}
