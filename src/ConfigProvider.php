<?php

declare(strict_types=1);
/**
 * This file is part of hyperf-ext/auth.
 *
 * @link     https://github.com/hyperf-ext/auth
 * @contact  eric@zhu.email
 * @license  https://github.com/hyperf-ext/auth/blob/master/LICENSE
 */
namespace HyperfExt\Auth;

use HyperfExt\Auth\Access\GateManager;
use HyperfExt\Auth\Commands\GenAuthPolicyCommand;
use HyperfExt\Auth\Contracts\Access\GateManagerInterface;
use HyperfExt\Auth\Contracts\AuthManagerInterface;
use HyperfExt\Auth\Contracts\PasswordBrokerManagerInterface;
use HyperfExt\Auth\Passwords\PasswordBrokerManager;

class ConfigProvider
{
    public function __invoke(): array
    {
        return [
            'dependencies' => [
                AuthManagerInterface::class => AuthManager::class,
                GateManagerInterface::class => GateManager::class,
                PasswordBrokerManagerInterface::class => PasswordBrokerManager::class,
            ],
            'annotations' => [
                'scan' => [
                    'paths' => [
                        __DIR__,
                    ],
                    'ignore_annotations' => [
                        'mixin',
                    ],
                ],
            ],
            'commands' => [
                GenAuthPolicyCommand::class,
            ],
            'publish' => [
                [
                    'id' => 'config',
                    'description' => 'The config for hyperf-ext/auth.',
                    'source' => __DIR__ . '/../publish/auth.php',
                    'destination' => BASE_PATH . '/config/autoload/auth.php',
                ],
            ],
        ];
    }
}
