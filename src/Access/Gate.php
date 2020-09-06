<?php

declare(strict_types=1);
/**
 * This file is part of hyperf-ext/auth.
 *
 * @link     https://github.com/hyperf-ext/auth
 * @contact  eric@zhu.email
 * @license  https://github.com/hyperf-ext/auth/blob/master/LICENSE
 */
namespace HyperfExt\Auth\Access;

use Exception;
use Hyperf\Contract\ContainerInterface;
use Hyperf\Utils\Arr;
use Hyperf\Utils\Str;
use HyperfExt\Auth\Contracts\Access\GateInterface;
use HyperfExt\Auth\Contracts\AuthenticatableInterface;
use HyperfExt\Auth\Exceptions\AuthorizationException;
use InvalidArgumentException;
use ReflectionClass;
use ReflectionFunction;

class Gate implements GateInterface
{
    use HandlesAuthorization;

    /**
     * The container instance.
     *
     * @var \Hyperf\Contract\ContainerInterface
     */
    protected $container;

    /**
     * The user resolver callable.
     *
     * @var callable
     */
    protected $userResolver;

    /**
     * All of the defined abilities.
     *
     * @var array
     */
    protected $abilities = [];

    /**
     * All of the defined policies.
     *
     * @var array
     */
    protected $policies = [];

    /**
     * All of the registered before callbacks.
     *
     * @var array
     */
    protected $beforeCallbacks = [];

    /**
     * All of the registered after callbacks.
     *
     * @var array
     */
    protected $afterCallbacks = [];

    /**
     * All of the defined abilities using class@method notation.
     *
     * @var array
     */
    protected $stringCallbacks = [];

    /**
     * The callback to be used to guess policy names.
     *
     * @var null|callable
     */
    protected $guessPolicyNamesUsingCallback;

    /**
     * Create a new gate instance.
     */
    public function __construct(
        ContainerInterface $container,
        callable $userResolver,
        array $abilities = [],
        array $policies = [],
        array $beforeCallbacks = [],
        array $afterCallbacks = [],
        ?callable $guessPolicyNamesUsingCallback = null
    ) {
        $this->policies = $policies;
        $this->container = $container;
        $this->abilities = $abilities;
        $this->userResolver = $userResolver;
        $this->afterCallbacks = $afterCallbacks;
        $this->beforeCallbacks = $beforeCallbacks;
        $this->guessPolicyNamesUsingCallback = $guessPolicyNamesUsingCallback;
    }

    /**
     * Determine if a given ability has been defined.
     *
     * @param string|string[] $ability
     */
    public function has($ability): bool
    {
        $abilities = is_array($ability) ? $ability : func_get_args();

        foreach ($abilities as $ability) {
            if (! isset($this->abilities[$ability])) {
                return false;
            }
        }

        return true;
    }

    /**
     * Define a new ability.
     *
     * @param callable|string $callback
     *
     * @throws \InvalidArgumentException
     * @return $this
     */
    public function define(string $ability, $callback)
    {
        if (is_array($callback) && isset($callback[0]) && is_string($callback[0])) {
            $callback = $callback[0] . '@' . $callback[1];
        }

        if (is_callable($callback)) {
            $this->abilities[$ability] = $callback;
        } elseif (is_string($callback)) {
            $this->stringCallbacks[$ability] = $callback;

            $this->abilities[$ability] = $this->buildAbilityCallback($ability, $callback);
        } else {
            throw new InvalidArgumentException("Callback must be a callable or a 'Class@method' string.");
        }

        return $this;
    }

    /**
     * Define abilities for a resource.
     *
     * @return $this
     */
    public function resource(string $name, string $class, array $abilities = null)
    {
        $abilities = $abilities ?: [
            'viewAny' => 'viewAny',
            'view' => 'view',
            'create' => 'create',
            'update' => 'update',
            'delete' => 'delete',
        ];

        foreach ($abilities as $ability => $method) {
            $this->define($name . '.' . $ability, $class . '@' . $method);
        }

        return $this;
    }

    /**
     * Define a policy class for a given class type.
     *
     * @return $this
     */
    public function policy(string $class, string $policy)
    {
        $this->policies[$class] = $policy;

        return $this;
    }

    /**
     * Register a callback to run before all Gate checks.
     *
     * @return $this
     */
    public function before(callable $callback)
    {
        $this->beforeCallbacks[] = $callback;

        return $this;
    }

    /**
     * Register a callback to run after all Gate checks.
     *
     * @return $this
     */
    public function after(callable $callback)
    {
        $this->afterCallbacks[] = $callback;

        return $this;
    }

    /**
     * Determine if the given ability should be granted for the current user.
     *
     * @param array|mixed $arguments
     */
    public function allows(string $ability, $arguments = []): bool
    {
        return $this->check($ability, $arguments);
    }

    /**
     * Determine if the given ability should be denied for the current user.
     *
     * @param array|mixed $arguments
     */
    public function denies(string $ability, $arguments = []): bool
    {
        return ! $this->allows($ability, $arguments);
    }

    /**
     * Determine if all of the given abilities should be granted for the current user.
     *
     * @param iterable|string $abilities
     * @param array|mixed $arguments
     */
    public function check($abilities, $arguments = []): bool
    {
        return collect($abilities)->every(function ($ability) use ($arguments) {
            return $this->inspect($ability, $arguments)->allowed();
        });
    }

    /**
     * Determine if any one of the given abilities should be granted for the current user.
     *
     * @param iterable|string $abilities
     * @param array|mixed $arguments
     */
    public function any($abilities, $arguments = []): bool
    {
        return collect($abilities)->contains(function ($ability) use ($arguments) {
            return $this->check($ability, $arguments);
        });
    }

    /**
     * Determine if all of the given abilities should be denied for the current user.
     *
     * @param iterable|string $abilities
     * @param array|mixed $arguments
     */
    public function none($abilities, $arguments = []): bool
    {
        return ! $this->any($abilities, $arguments);
    }

    /**
     * Determine if the given ability should be granted for the current user.
     *
     * @param array|mixed $arguments
     *
     *@throws \HyperfExt\Auth\Exceptions\AuthorizationException
     * @return \HyperfExt\Auth\Access\Response
     */
    public function authorize(string $ability, $arguments = []): Response
    {
        return $this->inspect($ability, $arguments)->authorize();
    }

    /**
     * Inspect the user for the given ability.
     *
     * @param array|mixed $arguments
     *
     * @return \HyperfExt\Auth\Access\Response
     */
    public function inspect(string $ability, $arguments = []): Response
    {
        try {
            $result = $this->raw($ability, $arguments);

            if ($result instanceof Response) {
                return $result;
            }

            return $result ? Response::allow() : Response::deny();
        } catch (AuthorizationException $e) {
            return $e->toResponse();
        }
    }

    /**
     * Get the raw result from the authorization callback.
     *
     * @param array|mixed $arguments
     *
     *@throws \HyperfExt\Auth\Exceptions\AuthorizationException
     * @return null|bool|\HyperfExt\Auth\Access\Response
     */
    public function raw(string $ability, $arguments = [])
    {
        $arguments = Arr::wrap($arguments);

        $user = $this->resolveUser();

        // First we will call the "before" callbacks for the Gate. If any of these give
        // back a non-null response, we will immediately return that result in order
        // to let the developers override all checks for some authorization cases.
        $result = $this->callBeforeCallbacks(
            $user,
            $ability,
            $arguments
        );

        if (is_null($result)) {
            $result = $this->callAuthCallback($user, $ability, $arguments);
        }

        // After calling the authorization callback, we will call the "after" callbacks
        // that are registered with the Gate, which allows a developer to do logging
        // if that is required for this application. Then we'll return the result.
        return $this->callAfterCallbacks(
            $user,
            $ability,
            $arguments,
            $result
        );
    }

    /**
     * Get a policy instance for a given class.
     *
     * @param object|string $class
     *
     * @return mixed|void
     */
    public function getPolicyFor($class)
    {
        if (is_object($class)) {
            $class = get_class($class);
        }

        if (! is_string($class)) {
            return;
        }

        if (isset($this->policies[$class])) {
            return $this->resolvePolicy($this->policies[$class]);
        }

        foreach ($this->guessPolicyName($class) as $guessedPolicy) {
            if (class_exists($guessedPolicy)) {
                return $this->resolvePolicy($guessedPolicy);
            }
        }

        foreach ($this->policies as $expected => $policy) {
            if (is_subclass_of($class, $expected)) {
                return $this->resolvePolicy($policy);
            }
        }
    }

    /**
     * Build a policy class instance of the given type.
     *
     * @param object|string $class
     *
     * @return mixed
     */
    public function resolvePolicy($class)
    {
        return $this->container->make($class);
    }

    /**
     * Get a gate instance for the given user.
     *
     * @return static
     */
    public function forUser(AuthenticatableInterface $user)
    {
        $callback = function () use ($user) {
            return $user;
        };

        return new static(
            $this->container, $callback, $this->abilities,
            $this->policies, $this->beforeCallbacks, $this->afterCallbacks,
            $this->guessPolicyNamesUsingCallback
        );
    }

    /**
     * Get all of the defined abilities.
     */
    public function abilities(): array
    {
        return $this->abilities;
    }

    /**
     * Get all of the defined policies.
     */
    public function policies(): array
    {
        return $this->policies;
    }

    /**
     * Specify a callback to be used to guess policy names.
     *
     * @return $this
     */
    public function guessPolicyNamesUsing(callable $callback)
    {
        $this->guessPolicyNamesUsingCallback = $callback;

        return $this;
    }

    /**
     * Create the ability callback for a callback string.
     *
     * @return \Closure
     */
    protected function buildAbilityCallback(string $ability, string $callback)
    {
        return function () use ($ability, $callback) {
            if (Str::contains($callback, '@')) {
                [$class, $method] = Str::parseCallback($callback);
            } else {
                $class = $callback;
            }

            $policy = $this->resolvePolicy($class);

            $arguments = func_get_args();

            $user = array_shift($arguments);

            $result = $this->callPolicyBefore(
                $policy,
                $user,
                $ability,
                $arguments
            );

            if (! is_null($result)) {
                return $result;
            }

            return isset($method)
                ? $policy->{$method}(...func_get_args())
                : $policy(...func_get_args());
        };
    }

    /**
     * Determine whether the callback/method can be called with the given user.
     *
     * @param array|\Closure|string $class
     *
     * @throws \ReflectionException
     */
    protected function canBeCalledWithUser(?AuthenticatableInterface $user, $class, ?string $method = null): bool
    {
        if (! is_null($user)) {
            return true;
        }

        if (! is_null($method)) {
            return $this->methodAllowsGuests($class, $method);
        }

        if (is_array($class)) {
            $className = is_string($class[0]) ? $class[0] : get_class($class[0]);

            return $this->methodAllowsGuests($className, $class[1]);
        }

        return $this->callbackAllowsGuests($class);
    }

    /**
     * Determine if the given class method allows guests.
     *
     * @param callable|string $class
     */
    protected function methodAllowsGuests($class, string $method): bool
    {
        try {
            $reflection = new ReflectionClass($class);

            $method = $reflection->getMethod($method);
        } catch (Exception $e) {
            return false;
        }

        if ($method) {
            $parameters = $method->getParameters();

            return isset($parameters[0]) && $this->parameterAllowsGuests($parameters[0]);
        }

        return false;
    }

    /**
     * Determine if the callback allows guests.
     *
     * @throws \ReflectionException
     */
    protected function callbackAllowsGuests(callable $callback): bool
    {
        $parameters = (new ReflectionFunction($callback))->getParameters();

        return isset($parameters[0]) && $this->parameterAllowsGuests($parameters[0]);
    }

    /**
     * Determine if the given parameter allows guests.
     *
     * @throws \ReflectionException
     */
    protected function parameterAllowsGuests(\ReflectionParameter $parameter): bool
    {
        return ($parameter->hasType() && $parameter->allowsNull()) ||
            ($parameter->isDefaultValueAvailable() && is_null($parameter->getDefaultValue()));
    }

    /**
     * Resolve and call the appropriate authorization callback.
     *
     * @throws \ReflectionException
     * @return bool|\HyperfExt\Auth\Access\Response
     */
    protected function callAuthCallback(?AuthenticatableInterface $user, string $ability, array $arguments)
    {
        $callback = $this->resolveAuthCallback($user, $ability, $arguments);

        return $callback($user, ...$arguments);
    }

    /**
     * Call all of the before callbacks and return if a result is given.
     *
     * @throws \ReflectionException
     * @return null|bool|\HyperfExt\Auth\Access\Response
     */
    protected function callBeforeCallbacks(?AuthenticatableInterface $user, string $ability, array $arguments)
    {
        foreach ($this->beforeCallbacks as $before) {
            if (! $this->canBeCalledWithUser($user, $before)) {
                continue;
            }

            if (! is_null($result = $before($user, $ability, $arguments))) {
                return $result;
            }
        }
        return null;
    }

    /**
     * Call all of the after callbacks with check result.
     *
     * @param null|bool|\HyperfExt\Auth\Access\Response $result
     *
     * @throws \ReflectionException
     * @return null|bool|\HyperfExt\Auth\Access\Response
     */
    protected function callAfterCallbacks(?AuthenticatableInterface $user, string $ability, array $arguments, $result)
    {
        foreach ($this->afterCallbacks as $after) {
            if (! $this->canBeCalledWithUser($user, $after)) {
                continue;
            }

            $afterResult = $after($user, $ability, $result, $arguments);

            $result = $result instanceof Response
                ? ($result->allowed() ? $result : $afterResult)
                : ($result ?? $afterResult);
        }

        return $result;
    }

    /**
     * Resolve the callable for the given ability and arguments.
     *
     * @throws \ReflectionException
     * @return callable
     */
    protected function resolveAuthCallback(?AuthenticatableInterface $user, string $ability, array $arguments)
    {
        if (isset($arguments[0]) &&
            ! is_null($policy = $this->getPolicyFor($arguments[0])) &&
            $callback = $this->resolvePolicyCallback($user, $ability, $arguments, $policy)) {
            return $callback;
        }

        if (isset($this->stringCallbacks[$ability])) {
            [$class, $method] = Str::parseCallback($this->stringCallbacks[$ability]);

            if ($this->canBeCalledWithUser($user, $class, $method ?: '__invoke')) {
                return $this->abilities[$ability];
            }
        }

        if (isset($this->abilities[$ability]) &&
            $this->canBeCalledWithUser($user, $this->abilities[$ability])) {
            return $this->abilities[$ability];
        }

        return function () {
        };
    }

    /**
     * Guess the policy name for the given class.
     */
    protected function guessPolicyName(string $class): array
    {
        if ($this->guessPolicyNamesUsingCallback) {
            return Arr::wrap(call_user_func($this->guessPolicyNamesUsingCallback, $class));
        }

        $classDirname = str_replace('/', '\\', dirname(str_replace('\\', '/', $class)));

        return [$classDirname . '\\Policy\\' . class_basename($class) . 'Policy'];
    }

    /**
     * Resolve the callback for a policy check.
     *
     * @param mixed $policy
     *
     * @return bool|callable
     */
    protected function resolvePolicyCallback(?AuthenticatableInterface $user, string $ability, array $arguments, $policy)
    {
        if (! is_callable([$policy, $this->formatAbilityToMethod($ability)])) {
            return false;
        }

        return function () use ($user, $ability, $arguments, $policy) {
            // This callback will be responsible for calling the policy's before method and
            // running this policy method if necessary. This is used to when objects are
            // mapped to policy objects in the user's configurations or on this class.
            $result = $this->callPolicyBefore(
                $policy,
                $user,
                $ability,
                $arguments
            );

            // When we receive a non-null result from this before method, we will return it
            // as the "final" results. This will allow developers to override the checks
            // in this policy to return the result for all rules defined in the class.
            if (! is_null($result)) {
                return $result;
            }

            $method = $this->formatAbilityToMethod($ability);

            return $this->callPolicyMethod($policy, $method, $user, $arguments);
        };
    }

    /**
     * Call the "before" method on the given policy, if applicable.
     *
     * @param mixed $policy
     *
     * @throws \ReflectionException
     * @return mixed|void
     */
    protected function callPolicyBefore($policy, ?AuthenticatableInterface $user, string $ability, array $arguments)
    {
        if (! method_exists($policy, 'before')) {
            return;
        }

        if ($this->canBeCalledWithUser($user, $policy, 'before')) {
            return $policy->before($user, $ability, ...$arguments);
        }
    }

    /**
     * Call the appropriate method on the given policy.
     *
     * @param mixed $policy
     *
     * @throws \ReflectionException
     * @return mixed|void
     */
    protected function callPolicyMethod($policy, string $method, ?AuthenticatableInterface $user, array $arguments)
    {
        // If this first argument is a string, that means they are passing a class name
        // to the policy. We will remove the first argument from this argument array
        // because this policy already knows what type of models it can authorize.
        if (isset($arguments[0]) && is_string($arguments[0])) {
            array_shift($arguments);
        }

        if (! is_callable([$policy, $method])) {
            return;
        }

        if ($this->canBeCalledWithUser($user, $policy, $method)) {
            return $policy->{$method}($user, ...$arguments);
        }
    }

    /**
     * Format the policy ability into a method name.
     */
    protected function formatAbilityToMethod(string $ability): string
    {
        return strpos($ability, '-') !== false ? Str::camel($ability) : $ability;
    }

    /**
     * Resolve the user from the user resolver.
     *
     * @return mixed
     */
    protected function resolveUser()
    {
        return call_user_func($this->userResolver);
    }
}
