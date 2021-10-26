<?php

namespace TahaKhram\LaravelAdb2cOpenid;

use Closure;

use Illuminate\Http\Request;

use GuzzleHttp\Client;
use GuzzleHttp\Exception\RequestException;

use Auth;
use TahaKhram\LaravelAdb2cOpenid\EndPointHandler;
use TahaKhram\LaravelAdb2cOpenid\TokenChecker;
use Illuminate\Support\Facades\Hash;

class AdB2C
{

    // protected $route2 = "/oauth2/v2.0/";
    // protected $route = "/oauth2/";

    public function __construct()
    {
        $this->login_route = config('azure.login_azure');
        $this->baseUrl = config('azure.endpoint_begin');
        $this->generic_policy = config('azure.generic_policy');
    }

    /**
     * Handle an incoming request
     *
     * @param \Illuminate\Http\Request $request
     * @param Closure $next
     * @return \Illuminate\Http\RedirectResponse|\Illuminate\Routing\Redirector|mixed
     * @throws \Exception
     */
    // public function handle($request, Closure $next)
    // {
    //     $access_token = $request->session()->get('_th_azure_access_token');
    //     $refresh_token = $request->session()->get('_th_azure_refresh_token');

    //     if (config('app.env') === "testing")
    //     {
    //         return $this->handleTesting($request, $next, $access_token, $refresh_token);
    //     }

    //     if (!$access_token || !$refresh_token)
    //     {
    //         return $this->redirect($request);
    //     }

    //     $client = new Client();

    //     try {
    //         $response = $client->request('POST', $this->baseUrl . config('azure.tenant_id') . $this->route . "token", [
    //             'form_params' => [
    //                 'grant_type' => 'refresh_token',
    //                 'client_id' => config('azure.client.id'),
    //                 'client_secret' => config('azure.client.secret'),
    //                 'refresh_token' => $refresh_token,
    //                 'resource' => config('azure.resource'),
    //             ]
    //         ]);

    //         $contents = json_decode($response->getBody()->getContents());
    //     } catch(RequestException $e) {
    //         $this->fail($request, $e);
    //     }

    //     if (empty($contents->access_token) || empty($contents->refresh_token)) {
    //         $this->fail($request, new \Exception('Missing tokens in response contents'));
    //     }
        
    //     $request->session()->put('_th_azure_access_token', $contents->access_token);
    //     $request->session()->put('_th_azure_refresh_token', $contents->refresh_token);

    //     return $this->handlecallback($request, $next, $access_token, $refresh_token);
    // }

    /**
     * Handle an incoming request in a testing environment
     * Assumes tester is calling actingAs or loginAs during testing to run this correctly
     *
     * @param \Illuminate\Http\Request $request
     * @param Closure $next
     * @return \Illuminate\Http\RedirectResponse|\Illuminate\Routing\Redirector|mixed
     */
    protected function handleTesting(Request $request, Closure $next)
    {
        $user = Auth::user();

        if (!isset($user))
        {
            return $this->redirect($request, $next);
        }

        return $this->handlecallback($request, $next, null, null);
    }

    /**
     * Redirects to the Azure route.  Typically used to point a web route to this method.
     * For example: Route::get('/login/azure', '\RootInc\LaravelAzureMiddleware\Azure@azure');
     *
     * @param \Illuminate\Http\Request $request
     * @return \Illuminate\Http\RedirectResponse|\Illuminate\Routing\Redirector|mixed
     */
    public function azure(Request $request)
    {
        $token = Hash::make('azure_secure' . date('Y-m-d') . url('/'));
        // Gets the azure url
        $endpoint_handler = new EndpointHandler($this->generic_policy);
        $authorization_endpoint = $endpoint_handler->getAuthorizationEndpoint().'&state=generic%20'.$token;
        return redirect()->away( $authorization_endpoint );
    }

    /**
     * Customized Redirect method
     *
     * @param \Illuminate\Http\Request $request
     * @return \Illuminate\Http\RedirectResponse|\Illuminate\Routing\Redirector|mixed
     */
    protected function redirect(Request $request)
    {
        return redirect()->guest($this->login_route);
    }

    /**
     * Callback after login from Azure
     *
     * @param \Illuminate\Http\Request $request
     * @return \Illuminate\Http\RedirectResponse|\Illuminate\Routing\Redirector|mixed
     * @throws \Exception
     */
    public function azurecallback(Request $request)
    {
        $code = $request->input('code');
        $id_token = $request->input('id_token');
          
        $state = explode(" ", $request->input('state')); 
        $action = $state[0];
        $state_cookie = $state[1];
        if ( $code == NULL && $id_token == NULL) {
            $exception = new \Exception('ERROR - only id_token or code supported');
            return response()->view('errors.403', compact('exception'), 403);
        }
        if (Hash::check('azure_secure' . date('Y-m-d') . url('/'), $state[1]) == false) {
            $exception = new \Exception('Missing tokens in response contents');
            return response()->view('errors.403', compact('exception'), 403);
        }

        // Check which authorization policy was used
        if ($action == "generic") $policy = env('AZ_GENERIC_POLICY');
        if ($action == "admin") $policy = env('AZ_ADMIN_POLICY');
        if ($action == "edit_profile") $policy = env('AZ_EDIT_PROFILE_POLICY');

        // Check the response type
        if ($code != NULL ) {
        $resp = $code;
        $resp_type = "code";
        }
        else if ($id_token != NULL) {
        $resp = $id_token;
        $resp_type = "id_token";
        }

        // Verify token
        $tokenChecker = new TokenChecker($resp, $resp_type, env('AZ_CLIENT_ID'), env('AZ_CLIENT_SECRET'), $policy);
        $verified = $tokenChecker->authenticate();

        if ($verified == false) {
            $exception = new \Exception('Token validation error');
            return response()->view('errors.403', compact('exception'), 403);
        }


        // $client = new Client();

        // $code = $request->input('code');

        // try {
        //     $response = $client->request('POST', $this->baseUrl . config('azure.tenant_id') . $this->route . "token", [
        //         'form_params' => [
        //             'grant_type' => 'authorization_code',
        //             'client_id' => config('azure.client.id'),
        //             'client_secret' => config('azure.client.secret'),
        //             'code' => $code,
        //             'resource' => config('azure.resource'),
        //         ]
        //     ]);

        //     $contents = json_decode($response->getBody()->getContents());
        // } catch(RequestException $e) {
        //     return $this->fail($request, $e);
        // }

        // $access_token = $contents->access_token;
        // $refresh_token = $contents->refresh_token;
        // $profile = json_decode( base64_decode( explode(".", $contents->id_token)[1]) );

        // $request->session()->put('_th_azure_access_token', $access_token);
        // $request->session()->put('_th_azure_refresh_token', $refresh_token);

        // return $this->success($request, $access_token, $refresh_token, $profile);
    }

    /**
     * Handler that is called when a successful login has taken place for the first time
     *
     * @param \Illuminate\Http\Request $request
     * @param String $access_token
     * @param String $refresh_token
     * @param mixed $profile
     * @return \Illuminate\Http\RedirectResponse|\Illuminate\Routing\Redirector|mixed
     */
    protected function success(Request $request, $access_token, $refresh_token, $profile)
    {
        return redirect()->intended("/");
    }

    /**
     * Handler that is called when a failed handshake has taken place
     *
     * @param \Illuminate\Http\Request $request
     * @param \Exception $e
     * @return string
     */
    protected function fail(Request $request, \Exception $e)
    {
        // JustinByrne updated the original code from smitthhyy (18 Dec 2019) to change to an array to allow for multiple error codes.
        if ($request->isMethod('get'))  {
            $errorDescription = trim(substr($request->query('error_description', 'SOMETHING_ELSE'), 0, 11));
            
            $azureErrors = [
                'AADSTS50105' => [
                    'HTTP_CODE' => '403',
                    'msg' => 'User is not authorized within Azure AD to access this application.',
                ],
                'AADSTS90072' => [
                    'HTTP_CODE' => '403',
                    'msg' => 'The logged on User is not in the allowed Tenant. Log in with a User in the allowed Tenant.',
                ],
            ];

            if (array_key_exists($errorDescription, $azureErrors)) {
                return abort($azureErrors[$errorDescription]['HTTP_CODE'], $azureErrors[$errorDescription]['msg']);
            }
        }
        
        return implode("", explode(PHP_EOL, $e->getMessage()));
    }

    /**
     * Handler that is called every request when a user is logged in
     *
     * @param \Illuminate\Http\Request $request
     * @param Closure $next
     * @param String $access_token
     * @param String $refresh_token
     * @return \Illuminate\Http\RedirectResponse|\Illuminate\Routing\Redirector|mixed
     */
    protected function handlecallback(Request $request, Closure $next, $access_token, $refresh_token)
    {
        return $next($request);
    }

    /**
     * Gets the logout url
     *
     * @return String
     */
    public function getLogoutUrl()
    {
        return $this->baseUrl . "common" . $this->route . "logout";
    }

    /**
     * Redirects to the Azure logout route.  Typically used to point a web route to this method.
     * For example: Route::get('/logout/azure', '\RootInc\LaravelAzureMiddleware\Azure@azurelogout');
     *
     * @param \Illuminate\Http\Request $request
     * @return \Illuminate\Http\RedirectResponse|\Illuminate\Routing\Redirector|mixed
     */
    public function azurelogout(Request $request)
    {
        $request->session()->pull('_th_azure_access_token');
        $request->session()->pull('_th_azure_refresh_token');

        return redirect()->away($this->getLogoutUrl());
    }
}