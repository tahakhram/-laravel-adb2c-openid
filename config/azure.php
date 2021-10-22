<?php

return [
    /*
    |--------------------------------------------------------------------------
    | Tenant ID
    |--------------------------------------------------------------------------
    |
    | This value is equal to the 'Directory (tenant) ID' as found in the Azure
    | portal
    |
    */
    'tenant_id' => env('AZ_TENANT', ''),
    
    /*
    |--------------------------------------------------------------------------
    | Domain
    |--------------------------------------------------------------------------
    |
    | This value is equal to the 'Directory (tenant) Domain' as found in the Azure
    | portal
    |
    */
    'domain' => env('AZ_DOMAIN', ''),

    /*
    |--------------------------------------------------------------------------
    | Login URL
    |--------------------------------------------------------------------------
    |
    | This value is login URL for azure
    |
    */
    'login_azure' => 'login_azure',

    /*
    |--------------------------------------------------------------------------
    | Login URL
    |--------------------------------------------------------------------------
    |
    | This value is login URL for azure
    |
    */
    'login_azure' => 'login_azure',
    
    /*
    |--------------------------------------------------------------------------
    | Redirect URI
    |--------------------------------------------------------------------------
    |
    | This value is equal to the 'Redirect URI' as found in the Azure
    | portal
    |
    */
    'redirect_uri' => env('AZ_REDIRECT_URI', ''),

    /*
    |--------------------------------------------------------------------------
    | Response Type
    |--------------------------------------------------------------------------
    |
    | This value is equal to the 'Redirect Type' as found in the Azure
    | portal
    |
    */
    'response_type' => env('AZ_RESPONSE_TYPE', 'id_token'),

     /*
    |--------------------------------------------------------------------------
    | Response Mode
    |--------------------------------------------------------------------------
    |
    | This value is equal to the 'Redirect Mode' as found in the Azure
    | portal
    |
    */
    'response_mode' => env('AZ_RESPONSE_MODE', 'form_post'),

    /*
    |--------------------------------------------------------------------------
    | Permission Scope
    |--------------------------------------------------------------------------
    |
    | This value is equal to the 'Permission Scope' as found in the Azure
    | portal
    |
    */
    'scope' => env('AZ_SCOPE', 'openid offline_access'),

    /*
    |--------------------------------------------------------------------------
    | Generic Policy
    |--------------------------------------------------------------------------
    |
    | This value is equal to the 'Permission Scope' as found in the Azure
    | portal
    |
    */
    'generic_policy' => env('AZ_GENERIC_POLICY', ''),

    /*
    |--------------------------------------------------------------------------
    | Generic Policy
    |--------------------------------------------------------------------------
    |
    | This value is equal to the 'Permission Scope' as found in the Azure
    | portal
    |
    */
    'generic_policy' => env('AZ_GENERIC_POLICY', ''),

    /*
    |--------------------------------------------------------------------------
    | Client Info
    |--------------------------------------------------------------------------
    |
    | These values are equal to 'Application (client) ID' and the secret you
    | made in 'Client secrets' as found in the Azure portal
    |
    */
    'client' => [
        'id' => env('AZ_CLIENT_ID', ''),
        'secret' => env('AZ_CLIENT_SECRET', ''),
    ],

    /*
    |--------------------------------------------------------------------------
    | Endpoint URL (begin)
    |--------------------------------------------------------------------------
    |
    | This value is equal to the 'Permission Scope' as found in the Azure
    | portal
    |
    */
    'endpoint_begin' => env('AZ_ENDPOINT_BEGIN', ''),
    
    /*
    |--------------------------------------------------------------------------
    | Resource ID
    |--------------------------------------------------------------------------
    |
    | This value is equal to the 'Object ID' as found in the Azure portal
    |
    */
    'resource' => env('AZURE_RESOURCE', ''),

    /*
    |--------------------------------------------------------------------------
    | Domain Hint
    |--------------------------------------------------------------------------
    |
    | This value can be used to help users know which email address they
    | should login with.
    | https://azure.microsoft.com/en-us/updates/app-service-auth-and-azure-ad-domain-hints/
    |
    */
    'domain_hint' => env('AZ_DOMAIN_HINT', ''),

    /*
    |--------------------------------------------------------------------------
    | Login Hint
    |--------------------------------------------------------------------------
    |
    | This value can be used to help users know which email address they
    | should login with.
    | https://azure.microsoft.com/en-us/updates/app-service-auth-and-azure-ad-domain-hints/
    |
    */
    'login_hint' => env('AZ_LOGIN_HINT', ''),

];