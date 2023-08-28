<?php

namespace App\Http\Controllers;

use App\Http\Resources\UserResource;
use App\Models\quiz;
use Illuminate\Support\Facades\Validator;
use Illuminate\Support\Facades\Hash;
use Illuminate\Http\Request;
use App\Models\User;
use Tymon\JWTAuth\Facades\JWTAuth;
use Ramsey\Uuid\Uuid;
class AuthController extends Controller
{

    public function register(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'name' => 'required',
            'email' => 'required|email|unique:users',
            'password' => 'required',
        ]);

        if ($validator->fails()) {
            return response()->json(['errors' => $validator->errors()], 400);
        } else {
            $user = new User;
            $user->name = $request->name;
            $user->email = $request->email;
            $user->password = Hash::make($request->password);
            $user->save();

            return response()->json([
                'message' => 'User Registered Successfully',
            ]);
        }
    }
    public function login(Request $request)
    {
        $credentials = $request->only('email', 'password');

        if ($token = JWTAuth::attempt($credentials, ['expires_in' => 15])) {
            return response()->json(['token' => $token]);
        }

        return response()->json(['error' => 'Bad credentials'], 400);
    }
    public function getUser()
    {
        // Get the token from the request headers
        $token = JWTAuth::getToken();

        if (!$token) {
            return response()->json(['error' => 'Token not provided'], 401);
        }

        try {
            // Attempt to authenticate the user using the token
            $user = JWTAuth::toUser($token);
            return new UserResource($user);
        } catch (\Exception $e) {
            return response()->json(['error' => 'Invalid token'], 401);
        }
    }
    public function logout()
    {
        // Get the token from the request headers
        $token = JWTAuth::getToken();

        if ($token) {
            // Invalidate (logout) the token
            JWTAuth::invalidate($token);
            return response()->json(['message' => 'Logged out successfully']);
        }

        return response()->json(['message' => 'Token not provided'], 401);
    }
    public function generateApiKey(){
        $token = JWTAuth::getToken();
       $apiKey = str_replace('-', '', Uuid::uuid4()->toString());
       $user = JWTAuth::toUser($token);
       $insert=User::where('email',$user->email);
        $insert->update([
            'apiKey'=>$apiKey
        ]);
        return response()->json(['message'=>$apiKey]);
    }
    public function viewQuiz(){
        $token = JWTAuth::getToken();
        $user = JWTAuth::toUser($token);
        $userProvidedApiKey = request()->query('apiKey');
        // $select=User::where('email',$user->email)->where('apiKey',$apiKey)->first();
        if($userProvidedApiKey===$user->apiKey){
            return response()->json([
                'message'=>'successful',
                'quiz'=>quiz::all()
            ],200);

        }else{
            return response()->json(['error'=>'Wrong APi Key'],400);
        }
    }
}
