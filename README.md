# Hyperf 认证组件

该组件移植了 Laravel Auth 组件（[illuminate/auth](https://github.com/illuminate/auth )）相对完整的功能特性，除了中间件传参和邮件通知。

* Hyperf 的中间件遵循 PSR-15 的规范，无法使用 Laravel 的方式通过路由向中间件传递值，故在实现上与 Laravel 不同，仅实现了一个基础的身份认证中间件抽象类 `HyperfExt\Auth\Middlewares\AbstractAuthenticateMiddleware`。
* 邮件（[illuminate/mail](https://github.com/illuminate/mail )）和通知（[illuminate/notifications](https://github.com/illuminate/notifications )）尚未移植完成。

该组件实现了两个自定义注解。
* Hyperf\Di\Annotations\AbstractAnnotation\Auth  
可用于类和方法，语法 `Auth({"GUARD_CONF_NAME"[, ...]}[, passable=bool])`：
  * 第一个参数为 Guard 名列表
  * 第二个 `passable` 可选参数默认值为 `false`，设置为 `true` 时未认证的用户也可以通过 Guard，不会抛出为认证的异常，在某些特殊情况下将会比较有用。例如，同一个 API 需要对认证用户和非认证用户展示不同的数据。

* Hyperf\Di\Annotations\AbstractAnnotation\Policy  
可用于类，语法 `Policy({"MODEL_FQCN"\[, ...\]})`：  
  * 参数为模型 FQCN 列表

另外，Gate 和策略的注册方法与 Laravel 不同。

Gate 可以通过注入 `HyperfExt\Auth\Contracts\Access\GateManagerInterface` 来调用实例的 `define` 方法注册。或者监听 `HyperfExt\Auth\Events\GateManagerResolved` 事件来在监听器中访问事件的 `gate` 属性（GateManagerInterface）来注册。

策略可以通过 `gen:policy` 命令来创建，例如 `gen:policy PostPolicy --model=App\\Model\\Post`。也可以在配置文件的 `policies` 中定义模型类和策略类的映射。

如需使用 JWT，请额外安装 [`hyperf-ext/jwt`](https://github.com/hyperf-ext/jwt) 组件。

## 安装

```shell script
composer require hyperf-ext/auth
```

## 发布配置

```shell script
php bin/hyperf.php vendor:publish hyperf-ext/auth
```

> 文件位于 `config/autoload/auth.php`。

## 配置

> 详细说明见配置文件。

## 使用

### 身份认证

文档待完成。

### 授权

文档待完成。