<?php

return [
    /*
    |--------------------------------------------------------------------------
    | Login URL
    |--------------------------------------------------------------------------
    |This value is login URL for azure
    */
    'login_azure' => 'login_azure',
    
    /*
    |--------------------------------------------------------------------------
    | Is Login Admin Azure
    |--------------------------------------------------------------------------
    | This value is admin login use azure
    */
    'is_login_admin_azure' => false,

    /*
    |--------------------------------------------------------------------------
    | Is Login Azure
    |--------------------------------------------------------------------------
    | This value is login use azure
    */
    'is_login_azure' => true,

    /*
    |--------------------------------------------------------------------------
    | Redirect URI
    |--------------------------------------------------------------------------
    | This value is equal to the 'Redirect URI' as found in the Azure
    | portal
    */
    'redirect_uri' => env('AZ_REDIRECT_URI', ''),
    
    /*
    |--------------------------------------------------------------------------
    | Response Type
    |--------------------------------------------------------------------------
    | This value is equal to the 'Redirect Type' as found in the Azure
    | portal
    */
    'response_type' => env('AZ_RESPONSE_TYPE', 'id_token'),

     /*
    |--------------------------------------------------------------------------
    | Response Mode
    |--------------------------------------------------------------------------
    | This value is equal to the 'Redirect Mode' as found in the Azure
    | portal
    */
    'response_mode' => env('AZ_RESPONSE_MODE', 'form_post'),

    /*
    |--------------------------------------------------------------------------
    | Permission Scope
    |--------------------------------------------------------------------------
    | This value is equal to the 'Permission Scope' as found in the Azure
    | portal
    */
    'scope' => env('AZ_SCOPE', 'openid'),


    /*
    |--------------------------------------------------------------------------
    |----------------------------GENERIC CONFIGS-------------------------------
    |--------------------------------------------------------------------------
    */
    /*
    |--------------------------------------------------------------------------
    | Tenant ID
    |--------------------------------------------------------------------------
    | This value is equal to the 'Directory (tenant) ID' as found in the Azure
    | portal
    */
    'tenant_id' => env('AZ_TENANT', ''),
    
    /*
    |--------------------------------------------------------------------------
    | Domain
    |--------------------------------------------------------------------------
    | This value is equal to the 'Directory (tenant) Domain' as found in the Azure
    | portal
    */
    'domain' => env('AZ_DOMAIN', ''),

    /*
    |--------------------------------------------------------------------------
    | Azure identifier id
    |--------------------------------------------------------------------------
    | This value is login user azure identifier
    */
    'uid_azure' => 'oid',

    /*
    |--------------------------------------------------------------------------
    | Generic Policy
    |--------------------------------------------------------------------------
    | This value is equal to the 'Permission Scope' as found in the Azure
    | portal
    */
    'generic_policy' => env('AZ_GENERIC_POLICY', ''),
    
    /*
    |--------------------------------------------------------------------------
    | Client Info
    |--------------------------------------------------------------------------
    | These values are equal to 'Application (client) ID' and the secret you
    | made in 'Client secrets' as found in the Azure portal
    */
    'client' => [
        'id' => env('AZ_CLIENT_ID', ''),
        'secret' => env('AZ_CLIENT_SECRET', ''),
    ],

    /*
    |--------------------------------------------------------------------------
    | Endpoint URL (begin)
    |--------------------------------------------------------------------------
    | This value is equal to the 'Permission Scope' as found in the Azure
    | portal
    */
    'endpoint_begin' => env('AZ_ENDPOINT_BEGIN', ''),


    /*
    |--------------------------------------------------------------------------
    |----------------------------ADMIN CONFIGS-------------------------------
    |--------------------------------------------------------------------------
    */
    /*
    |--------------------------------------------------------------------------
    | Tenant ID for admin login
    |--------------------------------------------------------------------------
    | This value is equal to the 'Directory (tenant) ID' as found in the Azure
    | portal
    */
    'admin_tenant_id' => env('AZ_ADMIN_TENANT', ''),
    
    /*
    |--------------------------------------------------------------------------
    | Domain for admin login
    |--------------------------------------------------------------------------
    | This value is equal to the 'Directory (tenant) Domain' as found in the Azure
    | portal
    */
    'admin_domain' => env('AZ_ADMIN_DOMAIN', ''),

    /*
    |--------------------------------------------------------------------------
    | Azure identifier id for admin login
    |--------------------------------------------------------------------------
    | This value is login user azure identifier
    */
    'admin_uid_azure' => 'oid',
    
    /*
    |--------------------------------------------------------------------------
    | Client Info for admin login
    |--------------------------------------------------------------------------
    | These values are equal to 'Application (client) ID' and the secret you
    | made in 'Client secrets' as found in the Azure portal
    */
    'admin_client' => [
        'id' => env('AZ_ADMIN_CLIENT_ID', ''),
        'secret' => env('AZ_ADMIN_CLIENT_SECRET', ''),
    ],

    /*
    |--------------------------------------------------------------------------
    | Endpoint URL (begin) for admin login
    |--------------------------------------------------------------------------
    | This value is equal to the 'Permission Scope' as found in the Azure
    | portal
    */
    'admin_endpoint_begin' => env('AZ_ADMIN_ENDPOINT_BEGIN', ''),

    /*
    |--------------------------------------------------------------------------
    | Admin Policy for admin login
    |--------------------------------------------------------------------------
    | This value is equal to the 'Permission Scope' as found in the Azure
    | portal
    */
    'admin_policy' => env('AZ_ADMIN_POLICY', ''),

];