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
use App\Models\User;

class AdB2C
{

    public function __construct()
    {
        $this->login_route = config('azure.login_azure');
        $this->baseUrl = config('azure.endpoint_begin');
        $this->generic_policy = config('azure.generic_policy');
        $this->admin_policy = config('azure.admin_policy');
        $this->policy = config('azure.generic_policy');
        $this->action = 'generic';
    }


    /**
     * Redirects to the Azure route.  Typically used to point a web route to this method.
     * For example: Route::get('/login/azure', '\TahaKhram\LaravelAdb2cOpenid\AdB2C@azure');
     *
     * @param \Illuminate\Http\Request $request
     * @return \Illuminate\Http\RedirectResponse|\Illuminate\Routing\Redirector|mixed
     */
    public function azure(Request $request, $id)
    {

        $token = Hash::make('azure_secure' . date('Y-m-d') . url('/'));
        $client = User::find($id);
        if($client->roles->pluck('name')->all()[0] === "Super Admin"){
            $this->policy = $this->admin_policy;
            $this->action == "admin";
        } 
        // Gets the azure url
        $endpoint_handler = new EndpointHandler($this->policy);
        $authorization_endpoint = $endpoint_handler->getAuthorizationEndpoint().'&state='. $this->action.'%20'.$id .'%20'.$token . '&login_hint=' . $client->email;
        
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
        $id = $state[1];
        $state_cookie = $state[2];

        if($request->input('error')){
            $exception = new \Exception('Azure login error - '.$request->input('error_description'));
            return response()->view('errors.403', compact('exception'), 403);
        }
        if ( $code == NULL && $id_token == NULL) {
            $exception = new \Exception('ERROR - only id_token or code supported');
            return response()->view('errors.403', compact('exception'), 403);
        }
        if (Hash::check('azure_secure' . date('Y-m-d') . url('/'), $state[2]) == false) {
            $exception = new \Exception('Missing tokens in response contents');
            return response()->view('errors.403', compact('exception'), 403);
        }
        $client = User::find($id);
        // Check which authorization policy was used
        if ($action == "generic") $this->policy = env('AZ_GENERIC_POLICY');
        if ($action == "admin") $this->policy = env('AZ_ADMIN_POLICY');

        // Check the response type
        $resp = ($code != NULL ) ? $code: $id_token;
        $resp_type = ($code != NULL ) ? "code": "id_token";

        // Verify token
        $tokenChecker = new TokenChecker($resp, $resp_type, env('AZ_CLIENT_ID'), env('AZ_CLIENT_SECRET'), $this->policy);
        $verified = $tokenChecker->authenticate();

        if ($verified == false) {
            $exception = new \Exception('Token validation error');
            return response()->view('errors.403', compact('exception'), 403);
        }
        $token_data = $tokenChecker->getPayload();

        if($client->azure_id === NULL){
            $input['azure_id'] = $token_data['oid'];
            $client->update($input);
        } else if($client->azure_id !== NULL && $client->azure_id !== $token_data[''.config("azure.uid_azure").'']){
            $exception = new \Exception('Azure login and Upkeeper login data differ');
            return response()->view('errors.403', compact('exception'), 403);
        }
        $request->session()->put('_th_azure_access_token', $resp);
        Auth::login($client);
        return $this->success($request, $resp, $token_data);
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
    protected function success(Request $request, $resp, $token_data)
    {
        return redirect()->intended("/");
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
     * For example: Route::get('/logout/azure', '\TahaKhram\LaravelAdb2cOpenid@azurelogout');
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