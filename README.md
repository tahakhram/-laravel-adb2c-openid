# laravel-adb2c-openid

Provides Azure AD B2C openid Authentication . 

## Normal Installation

1. `composer require tahakhram/laravel-adb2c-openid:~1.2`
2. run `php artisan vendor:publish --provider="TahaKhram\LaravelAdb2cOpenid\AdB2CServiceProvider"` to install config file to `config/azure.php`
3. In routes folder in `web.php` add

`Route::get('/login/azure', '\RootInc\LaravelAzureMiddleware\Azure@azure');`
`Route::get('/login/azurecallback', '\RootInc\LaravelAzureMiddleware\Azure@azurecallback');`
