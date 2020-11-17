<?php

namespace Spatie\Permission\Middlewares;

use Closure;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Config;
use Spatie\Permission\Exceptions\UnauthorizedException;

class RoleOrPermissionMiddleware
{
    public function handle($request, Closure $next, $roleOrPermission, $guard = null)
    {
        $authGuard = Auth::guard($guard);
        if ($authGuard->guest()) {
            throw UnauthorizedException::notLoggedIn();
        }
        $rolesOrPermissions = is_array($roleOrPermission)
            ? $roleOrPermission
            : explode('|', $roleOrPermission);

        $driverDatabase = Config::get('database.default', 'mysql');
        Config::set('database.default', Config::get('permission.spatie_database_driver'));

        if ( !$authGuard->user()->hasAnyRole($rolesOrPermissions) && !$authGuard->user()->hasAnyPermission($rolesOrPermissions)) {
            throw UnauthorizedException::forRolesOrPermissions($rolesOrPermissions);
        }
        Config::set('database.default', $driverDatabase);

        return $next($request);
    }
}

