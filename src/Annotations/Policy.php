<?php

declare(strict_types=1);
/**
 * This file is part of hyperf-ext/auth.
 *
 * @link     https://github.com/hyperf-ext/auth
 * @contact  eric@zhu.email
 * @license  https://github.com/hyperf-ext/auth/blob/master/LICENSE
 */
namespace HyperfExt\Auth\Annotations;

use Hyperf\Di\Annotation\AbstractAnnotation;
use InvalidArgumentException;

/**
 * @Annotation
 * @Target("CLASS")
 * @Attributes({
 *     @Attribute("models", type="array")
 * })
 */
class Policy extends AbstractAnnotation
{
    /**
     * @var string[]
     */
    public $models;

    public function __construct($value = null, $aa = null)
    {
        parent::__construct($value);
        if (isset($value['value'])) {
            $value['value'] = empty($value['value']) ? [] : (is_array($value['value']) ? array_unique($value['value']) : [$value['value']]);
            if (empty($value['value'])) {
                throw new InvalidArgumentException('Policy annotation requires at least one model.');
            }
            $this->models = $value['value'];
        }
    }
}
