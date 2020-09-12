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

use Hyperf\Command\Command as HyperfCommand;
use Hyperf\Contract\ConfigInterface;
use Hyperf\Utils\CodeGen\Project;
use Hyperf\Utils\Str;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputOption;

class GenAuthPolicyCommand extends HyperfCommand
{
    /**
     * @var \Hyperf\Contract\ConfigInterface
     */
    protected $config;

    public function __construct(ConfigInterface $config)
    {
        parent::__construct('gen:auth-policy');
        $this->config = $config;
    }

    public function configure()
    {
        parent::configure();
        $this->setDescription('Create a new access gate policy class');
        $this->addArgument('name', InputArgument::REQUIRED, 'The name of the class.');
        $this->addOption('path', 'p', InputOption::VALUE_OPTIONAL, 'The path that the policy file generates to.');
        $this->addOption('model', 'm', InputOption::VALUE_REQUIRED, 'The model that the policy applies to.');
        $this->addOption('guard', 'g', InputOption::VALUE_OPTIONAL, 'The guard that the policy relies on.');
    }

    /**
     * Handle the current command.
     */
    public function handle()
    {
        $name = $this->input->getArgument('name');
        $option = new PolicyOption();
        $option
            ->setPath($this->getOption('path', 'app/Policy'))
            ->setGuard($this->getOption('guard', $this->config->get('auth.default.guard', null)))
            ->setModel($this->getOption('model'));
        $this->createPolicy($name, $option);
    }

    protected function createPolicy(string $name, PolicyOption $option)
    {
        $project = new Project();
        $class = Str::studly(Str::singular($name));
        $class = $project->namespace($option->getPath()) . $class;
        $path = BASE_PATH . '/' . $project->path($class);

        if (! file_exists($path)) {
            $dir = dirname($path);
            if (! is_dir($dir)) {
                @mkdir($dir, 0755, true);
            }
            file_put_contents($path, $this->buildClass($name, $class, $option));
        }

        $this->output->writeln(sprintf('<info>Policy %s was created.</info>', $class));
    }

    /**
     * @param null|mixed $default
     *
     * @return null|mixed
     */
    protected function getOption(string $name, $default = null)
    {
        $result = $this->input->getOption($name);
        return empty($result) ? $default : $result;
    }

    /**
     * Build the class with the given name.
     */
    protected function buildClass(string $name, string $class, PolicyOption $option): string
    {
        $model = (string) $option->getModel();

        $namespace = $this->getNamespace($class);
        $namespacedUserModel = $this->getUserProviderModel($option->getGuard());
        $userModel = class_basename($namespacedUserModel);
        $namespacedModel = trim($model, '\\');
        $model = class_basename($namespacedModel);
        $modelVariable = Str::camel($model);
        $uses = [
            $namespacedUserModel,
            $namespacedModel,
        ];
        if ($namespacedUserModel === $namespacedModel) {
            $modelVariable = 'another' . ucfirst($modelVariable);
        }

        $replace = [
            '%NAMESPACE%' => $namespace,
            '%USER_MODEL%' => $userModel,
            '%NAMESPACED_MODEL%' => $namespacedModel,
            '%CLASS%' => $name,
            '%USES%' => $this->buildUses($uses),
            '%MODEL%' => $model,
            '%MODEL_VARIABLE%' => $modelVariable,
        ];

        return str_replace(array_keys($replace), array_values($replace), $this->getStub());
    }

    protected function buildUses(array $uses): string
    {
        $uses = array_map(function ($class) {
            return 'use ' . $class . ';';
        }, array_unique(array_filter($uses)));
        return implode("\n", $uses);
    }

    /**
     * Get the full namespace for a given class, without the class name.
     */
    protected function getNamespace(string $name): string
    {
        return trim(implode('\\', array_slice(explode('\\', $name), 0, -1)), '\\');
    }

    /**
     * Get the model for the guard's user provider.
     */
    protected function getUserProviderModel(?string $guard = null): ?string
    {
        $guard = $guard ?: $this->config->get('auth.default.guard');

        return $this->config->get(
            'auth.providers.' . $this->config->get('auth.guards.' . $guard . '.provider') . '.options.model'
        );
    }

    /**
     * Get the stub file for the generator.
     */
    protected function getStub(): string
    {
        return file_get_contents(__DIR__ . '/stub/policy.stub');
    }
}
