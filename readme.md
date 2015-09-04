## Laravel Redirect All Requests To HTTPS/SSL using middleware


### step1 - create middleware stub

```sh
php artisan make:middleware ForceSSL
```

### step2 - implemention middleware

 - modify app\Http\Middleware\ForceSSL.php.
 - register except uri in $except array.

```php
<?php

namespace App\Http\Middleware;

use Closure;

class ForceSSL
{
    // The URIs that should be excluded from force SSL.
    protected $except = [
        '/download/*',
    ];

    // The application environment that should be excluded from force SSL.
    protected $exceptEnv = [
        'local',
        'testing',
    ];

    /**
     * Handle an incoming request.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  \Closure  $next
     * @return mixed
     */
    public function handle($request, Closure $next)
    {
         if (!$request->secure() && !$this->shouldPassThrough($request) && !$this->envPassThrough()) {
            
            $secureUrl = 'https://' . $request->getHttpHost() . $request->getRequestUri();
            return redirect($secureUrl);
        }

        return $next($request);
    }

    protected function shouldPassThrough($request)
    {
        foreach ($this->except as $except) {
            if ($request->is($except)) {
                return true;
            }
        }
     
        return false;
    }

    protected function envPassThrough() 
    {
        $appEnv = \App::environment();

        foreach ($this->exceptEnv as $except) {
            if ($appEnv === $except)
                return true;
        }

        return false;  
    }
}
```

### step 3 - Registering Middleware
modify app\Http\Kernel.php and Assigning Middleware To Routes(global or routeMiddleware).

```php
class Kernel extends HttpKernel
{
    /**
     * The application's global HTTP middleware stack.
     *
     * @var array
     */
    protected $middleware = [
        \Illuminate\Foundation\Http\Middleware\CheckForMaintenanceMode::class,
        \App\Http\Middleware\EncryptCookies::class,
        \Illuminate\Cookie\Middleware\AddQueuedCookiesToResponse::class,
        \Illuminate\Session\Middleware\StartSession::class,
        \Illuminate\View\Middleware\ShareErrorsFromSession::class,
        \App\Http\Middleware\VerifyCsrfToken::class,
        // force ssl
        \App\Http\Middleware\ForceSSL::class,
    ];

    /**
     * The application's route middleware.
     *
     * @var array
     */
    protected $routeMiddleware = [
        'auth' => \App\Http\Middleware\Authenticate::class,
        'auth.basic' => \Illuminate\Auth\Middleware\AuthenticateWithBasicAuth::class,
        'guest' => \App\Http\Middleware\RedirectIfAuthenticated::class,
        'setup' => \App\Http\Middleware\SetupApp::class,
        'force.ssl' => \App\Http\Middleware\ForceSSL::class,
    ];
}
```

### step 4(routeMiddleware only)
Once the middleware has been defined in the routeMiddleware, you should use the middleware key in the route options array:

```php
Route::get('admin/profile', ['middleware' => ['force.ssl', 'auth'], function () {
    //
}]);
```
