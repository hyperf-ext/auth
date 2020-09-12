<?php

declare(strict_types=1);
/**
 * This file is part of hyperf-ext/auth.
 *
 * @link     https://github.com/hyperf-ext/auth
 * @contact  eric@zhu.email
 * @license  https://github.com/hyperf-ext/auth/blob/master/LICENSE
 */
namespace HyperfExt\Auth\Guards;

use Hyperf\Contract\SessionInterface;
use Hyperf\HttpMessage\Cookie\Cookie;
use Hyperf\Utils\Str;
use Hyperf\Utils\Traits\Macroable;
use HyperfExt\Auth\Contracts\AuthenticatableInterface;
use HyperfExt\Auth\Contracts\StatefulGuardInterface;
use HyperfExt\Auth\Contracts\SupportsBasicAuthInterface;
use HyperfExt\Auth\Contracts\UserProviderInterface;
use HyperfExt\Auth\EventHelpers;
use HyperfExt\Auth\Events\Logout;
use HyperfExt\Auth\Exceptions\AuthenticationException;
use HyperfExt\Auth\GuardHelpers;
use HyperfExt\Auth\Recaller;
use HyperfExt\Cookie\Contract\CookieJarInterface;
use HyperfExt\Hashing\Hash;
use Psr\EventDispatcher\EventDispatcherInterface;
use Psr\Http\Message\ServerRequestInterface;

class SessionGuard implements StatefulGuardInterface, SupportsBasicAuthInterface
{
    use EventHelpers;
    use GuardHelpers;
    use Macroable;

    /**
     * The name of the Guard. Typically "session".
     *
     * Corresponds to guard name in authentication configuration.
     *
     * @var string
     */
    protected $name;

    /**
     * The user we last attempted to retrieve.
     *
     * @var \HyperfExt\Auth\Contracts\AuthenticatableInterface
     */
    protected $lastAttempted;

    /**
     * Indicates if the user was authenticated via a recaller cookie.
     *
     * @var bool
     */
    protected $viaRemember = false;

    /**
     * The session used by the guard.
     *
     * @var \Hyperf\Contract\SessionInterface
     */
    protected $session;

    /**
     * The HyperfExt cookie jar instance.
     *
     * @var \HyperfExt\Cookie\CookieJar
     */
    protected $cookieJar;

    /**
     * The request instance.
     *
     * @var \Psr\Http\Message\ServerRequestInterface
     */
    protected $request;

    /**
     * The event dispatcher instance.
     *
     * @var \Psr\EventDispatcher\EventDispatcherInterface
     */
    protected $eventDispatcher;

    /**
     * Indicates if the logout method has been called.
     *
     * @var bool
     */
    protected $loggedOut = false;

    /**
     * Indicates if a token user retrieval has been attempted.
     *
     * @var bool
     */
    protected $recallAttempted = false;

    /**
     * Create a new authentication guard.
     */
    public function __construct(
        ServerRequestInterface $request,
        SessionInterface $session,
        EventDispatcherInterface $eventDispatcher,
        CookieJarInterface $cookieJar,
        UserProviderInterface $provider,
        string $name,
        array $options = []
    ) {
        $this->request = $request;
        $this->session = $session;
        $this->eventDispatcher = $eventDispatcher;
        $this->cookieJar = $cookieJar;
        $this->provider = $provider;
        $this->name = $options['name'] ?? 'session';
    }

    /**
     * Get the currently authenticated user.
     */
    public function user(): ?AuthenticatableInterface
    {
        if ($this->loggedOut) {
            return null;
        }

        // If we've already retrieved the user for the current request we can just
        // return it back immediately. We do not want to fetch the user data on
        // every call to this method because that would be tremendously slow.
        if (! is_null($this->user)) {
            return $this->user;
        }

        $id = $this->session->get($this->getName());

        // First we will try to load the user using the identifier in the session if
        // one exists. Otherwise we will check for a "remember me" cookie in this
        // request, and if one exists, attempt to retrieve the user using that.
        if (! is_null($id) && $this->user = $this->provider->retrieveById($id)) {
            $this->dispatchAuthenticatedEvent($this->user);
        }

        // If the user is null, but we decrypt a "recaller" cookie we can attempt to
        // pull the user data on that cookie which serves as a remember cookie on
        // the application. Once we have a user we can return it to the caller.
        if (is_null($this->user) && ! is_null($recaller = $this->recaller())) {
            $this->user = $this->userFromRecaller($recaller);

            if ($this->user) {
                $this->updateSession($this->user->getAuthIdentifier());

                $this->dispatchLoginEvent($this->user, true);
            }
        }

        return $this->user;
    }

    /**
     * Get the ID for the currently authenticated user.
     *
     * @return null|int|string
     */
    public function id()
    {
        if ($this->loggedOut) {
            return null;
        }

        return $this->user()
            ? $this->user()->getAuthIdentifier()
            : $this->session->get($this->getName());
    }

    /**
     * Log a user into the application without sessions or cookies.
     */
    public function once(array $credentials = []): bool
    {
        $this->dispatchAttemptingEvent($credentials);

        if ($this->validate($credentials)) {
            $this->setUser($this->lastAttempted);

            return true;
        }

        return false;
    }

    /**
     * Log the given user ID into the application without sessions or cookies.
     *
     * @param mixed $id
     *
     * @return false|\HyperfExt\Auth\Contracts\AuthenticatableInterface
     */
    public function onceUsingId($id)
    {
        if (! is_null($user = $this->provider->retrieveById($id))) {
            $this->setUser($user);

            return $user;
        }

        return false;
    }

    /**
     * Validate a user's credentials.
     */
    public function validate(array $credentials = []): bool
    {
        $this->lastAttempted = $user = $this->provider->retrieveByCredentials($credentials);

        return $this->hasValidCredentials($user, $credentials);
    }

    /**
     * Attempt to authenticate using HTTP Basic Auth.
     */
    public function basic(string $field = 'email', array $extraConditions = []): void
    {
        if ($this->check()) {
            return;
        }

        // If a username is set on the HTTP basic request, we will return out without
        // interrupting the request lifecycle. Otherwise, we'll need to generate a
        // request indicating that the given credentials were invalid for login.
        if ($this->attemptBasic($this->getRequest(), $field, $extraConditions)) {
            return;
        }

        $this->failedBasicResponse();
    }

    /**
     * Perform a stateless HTTP Basic login attempt.
     */
    public function onceBasic(string $field = 'email', array $extraConditions = []): void
    {
        $credentials = $this->basicCredentials($this->getRequest(), $field);

        if (! $this->once(array_merge($credentials, $extraConditions))) {
            $this->failedBasicResponse();
        }
    }

    /**
     * Attempt to authenticate a user using the given credentials.
     */
    public function attempt(array $credentials = [], bool $remember = false)
    {
        $this->dispatchAttemptingEvent($credentials, $remember);

        $this->lastAttempted = $user = $this->provider->retrieveByCredentials($credentials);

        // If an implementation of UserInterface was returned, we'll ask the provider
        // to validate the user against the given credentials, and if they are in
        // fact valid we'll log the users into the application and return true.
        if ($this->hasValidCredentials($user, $credentials)) {
            $this->login($user, $remember);

            return true;
        }

        // If the authentication attempt fails we will fire an event so that the user
        // may be notified of any suspicious attempts to access their account from
        // an unrecognized user. A developer may listen to this event as needed.
        $this->dispatchFailedEvent($user, $credentials);

        return false;
    }

    /**
     * Log the given user ID into the application.
     *
     * @param mixed $id
     */
    public function loginUsingId($id, bool $remember = false): ?AuthenticatableInterface
    {
        if (! is_null($user = $this->provider->retrieveById($id))) {
            $this->login($user, $remember);

            return $user;
        }

        return null;
    }

    /**
     * Log a user into the application.
     */
    public function login(AuthenticatableInterface $user, bool $remember = false)
    {
        $this->updateSession($user->getAuthIdentifier());

        // If the user should be permanently "remembered" by the application we will
        // queue a permanent cookie that contains the encrypted copy of the user
        // identifier. We will then decrypt this later to retrieve the users.
        if ($remember) {
            $this->ensureRememberTokenIsSet($user);

            $this->queueRecallerCookie($user);
        }

        // If we have an event dispatcher instance set we will fire an event so that
        // any listeners will hook into the authentication events and run actions
        // based on the login and logout events fired from the guard instances.
        $this->dispatchLoginEvent($user, $remember);

        $this->setUser($user);
    }

    /**
     * Log the user out of the application.
     */
    public function logout()
    {
        $user = $this->user();

        $this->clearUserDataFromStorage();

        if (! is_null($this->user) && ! empty($user->getRememberToken())) {
            $this->cycleRememberToken($user);
        }

        $this->dispatchLogoutEvent($user);

        // Once we have fired the logout event we will clear the users out of memory
        // so they are no longer available as the user is no longer considered as
        // being signed into this application and should not be available here.
        $this->user = null;

        $this->loggedOut = true;
    }

    /**
     * Log the user out of the application on their current device only.
     */
    public function logoutCurrentDevice()
    {
        $user = $this->user();

        $this->clearUserDataFromStorage();

        $this->dispatchCurrentDeviceLogoutEvent($user);

        // Once we have fired the logout event we will clear the users out of memory
        // so they are no longer available as the user is no longer considered as
        // being signed into this application and should not be available here.
        $this->user = null;

        $this->loggedOut = true;
    }

    /**
     * Invalidate other sessions for the current user.
     *
     * The application must be using the AuthenticateSession middleware.
     */
    public function logoutOtherDevices(string $password, string $attribute = 'password'): ?bool
    {
        if (! $this->user()) {
            return null;
        }

        $result = tap($this->user()->forceFill([
            $attribute => Hash::make($password),
        ]))->save();

        if ($this->recaller() || $this->cookieJar->hasQueued($this->getRecallerName())) {
            $this->queueRecallerCookie($this->user());
        }

        $this->dispatchOtherDeviceLogoutEvent($this->user());

        return $result;
    }

    /**
     * Get the last user we attempted to authenticate.
     */
    public function getLastAttempted(): AuthenticatableInterface
    {
        return $this->lastAttempted;
    }

    /**
     * Get a unique identifier for the auth session value.
     */
    public function getName(): string
    {
        return 'login_' . $this->name . '_' . sha1(static::class);
    }

    /**
     * Get the name of the cookie used to store the "recaller".
     */
    public function getRecallerName(): string
    {
        return 'remember_' . $this->name . '_' . sha1(static::class);
    }

    /**
     * Determine if the user was authenticated via "remember me" cookie.
     */
    public function viaRemember(): bool
    {
        return $this->viaRemember;
    }

    /**
     * Get the cookie creator instance used by the guard.
     *
     * @return \HyperfExt\Cookie\CookieJar
     */
    public function getCookieJar(): CookieJarInterface
    {
        return $this->cookieJar;
    }

    /**
     * Get the session store used by the guard.
     *
     * @return \Hyperf\Contract\SessionInterface
     */
    public function getSession()
    {
        return $this->session;
    }

    /**
     * Return the currently cached user.
     *
     * @return null|\HyperfExt\Auth\Contracts\AuthenticatableInterface
     */
    public function getUser()
    {
        return $this->user;
    }

    /**
     * Set the current user.
     *
     * @return $this
     */
    public function setUser(AuthenticatableInterface $user)
    {
        $this->user = $user;

        $this->loggedOut = false;

        $this->dispatchAuthenticatedEvent($user);

        return $this;
    }

    /**
     * Get the current request instance.
     */
    public function getRequest(): ServerRequestInterface
    {
        return $this->request;
    }

    /**
     * Set the current request instance.
     *
     * @return $this
     */
    public function setRequest(ServerRequestInterface $request)
    {
        $this->request = $request;
        return $this;
    }

    /**
     * Get the event dispatcher instance.
     */
    public function getEventDispatcher(): EventDispatcherInterface
    {
        return $this->eventDispatcher;
    }

    /**
     * Set the event dispatcher instance.
     */
    public function setEventDispatcher(EventDispatcherInterface $eventDispatcher): void
    {
        $this->eventDispatcher = $eventDispatcher;
    }

    /**
     * Pull a user from the repository by its "remember me" cookie token.
     *
     * @param \HyperfExt\Auth\Recaller $recaller
     */
    protected function userFromRecaller($recaller): ?AuthenticatableInterface
    {
        if (! $recaller->valid() || $this->recallAttempted) {
            return null;
        }

        // If the user is null, but we decrypt a "recaller" cookie we can attempt to
        // pull the user data on that cookie which serves as a remember cookie on
        // the application. Once we have a user we can return it to the caller.
        $this->recallAttempted = true;

        $this->viaRemember = ! is_null($user = $this->provider->retrieveByToken(
            $recaller->id(),
            $recaller->token()
        ));

        return $user;
    }

    /**
     * Get the decrypted recaller cookie for the request.
     */
    protected function recaller(): ?Recaller
    {
        if (is_null($this->request)) {
            return null;
        }

        if ($recaller = $this->request->cookie($this->getRecallerName())) {
            return new Recaller($recaller);
        }
        return null;
    }

    /**
     * Attempt to authenticate using basic authentication.
     */
    protected function attemptBasic(ServerRequestInterface $request, string $field, array $extraConditions = []): bool
    {
        if (empty($request->getHeaderLine('Authorization'))) {
            return false;
        }

        return $this->attempt(array_merge(
            $this->basicCredentials($request, $field),
            $extraConditions
        ));
    }

    /**
     * Get the credential array for a HTTP Basic request.
     *
     * @return string[]
     */
    protected function basicCredentials(ServerRequestInterface $request, string $field): array
    {
        $authorization = $this->getBasicAuthorization($request);
        return array_combine([$field, 'password'], $authorization);
    }

    /**
     * @return string[]
     */
    protected function getBasicAuthorization(ServerRequestInterface $request): array
    {
        $header = $request->getHeaderLine('Authorization');

        if (Str::startsWith($header, 'Basic ')) {
            try {
                return explode(':', base64_decode(Str::substr($header, 6)));
            } catch (\Throwable $throwable) {
            }
        }
        return [null, null];
    }

    /**
     * Get the response for basic authentication.
     *
     * @throws \HyperfExt\Auth\Exceptions\AuthenticationException
     */
    protected function failedBasicResponse(): void
    {
        throw new AuthenticationException('Invalid Basic credentials.');
    }

    /**
     * Determine if the user matches the credentials.
     *
     * @param mixed $user
     */
    protected function hasValidCredentials($user, array $credentials): bool
    {
        $validated = ! is_null($user) && $this->provider->validateCredentials($user, $credentials);

        if ($validated) {
            $this->dispatchValidatedEvent($user);
        }

        return $validated;
    }

    /**
     * Update the session with the given ID.
     *
     * @param int|string $id
     */
    protected function updateSession($id): void
    {
        $this->session->put($this->getName(), $id);

        $this->session->migrate(true);
    }

    /**
     * Create a new "remember me" token for the user if one doesn't already exist.
     */
    protected function ensureRememberTokenIsSet(AuthenticatableInterface $user): void
    {
        if (empty($user->getRememberToken())) {
            $this->cycleRememberToken($user);
        }
    }

    /**
     * Queue the recaller cookie into the cookie jar.
     */
    protected function queueRecallerCookie(AuthenticatableInterface $user): void
    {
        $this->cookieJar->queue($this->createRecaller(
            $user->getAuthIdentifier() . '|' . $user->getRememberToken() . '|' . $user->getAuthPassword()
        ));
    }

    /**
     * Create a "remember me" cookie for a given ID.
     */
    protected function createRecaller(string $value): Cookie
    {
        return $this->cookieJar->forever($this->getRecallerName(), $value);
    }

    /**
     * Remove the user data from the session and cookies.
     */
    protected function clearUserDataFromStorage()
    {
        $this->session->remove($this->getName());

        if (! is_null($this->recaller())) {
            $this->cookieJar->queue($this->cookieJar->forget($this->getRecallerName()));
        }
    }

    /**
     * Refresh the "remember me" token for the user.
     */
    protected function cycleRememberToken(AuthenticatableInterface $user)
    {
        $user->setRememberToken($token = Str::random(60));

        $this->provider->updateRememberToken($user, $token);
    }
}
