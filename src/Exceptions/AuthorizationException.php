<?php

declare(strict_types=1);
/**
 * This file is part of hyperf-ext/auth.
 *
 * @link     https://github.com/hyperf-ext/auth
 * @contact  eric@zhu.email
 * @license  https://github.com/hyperf-ext/auth/blob/master/LICENSE
 */
namespace HyperfExt\Auth\Exceptions;

use Exception;
use HyperfExt\Auth\Access\Response;
use Throwable;

class AuthorizationException extends Exception
{
    /**
     * The response from the gate.
     *
     * @var \HyperfExt\Auth\Access\Response
     */
    protected $response;

    /**
     * Create a new authorization exception instance.
     *
     * @param mixed $code
     */
    public function __construct(?string $message = null, $code = null, Throwable $previous = null)
    {
        parent::__construct($message ?? 'This action is unauthorized.', 0, $previous);

        $this->code = $code ?: 0;
    }

    /**
     * Get the response from the gate.
     */
    public function getResponse(): Response
    {
        return $this->response;
    }

    /**
     * Set the response from the gate.
     *
     * @return $this
     */
    public function setResponse(Response $response)
    {
        $this->response = $response;

        return $this;
    }

    /**
     * Create a deny response object from this exception.
     */
    public function toResponse(): Response
    {
        return Response::deny($this->message, $this->code);
    }
}
