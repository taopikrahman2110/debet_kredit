<?php

namespace App\Http\Controllers;


use App\Helpers\ResponseFormatter;
use App\Models\User;
use Illuminate\Auth\Events\Authenticated;
use Illuminate\Auth\Events\Failed;
use Illuminate\Http\Request;
use Laravel\Fortify\Rules\Password;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Storage;
use Illuminate\Support\Facades\Validator;
use Illuminate\Foundation\Bus\DispatchesJobs;
use Illuminate\Routing\Controller as BaseController;
use Illuminate\Foundation\Validation\ValidatesRequests;
use Illuminate\Foundation\Auth\Access\AuthorizesRequests;
use App\Http\Controllers\Controller;

class UserController extends Controller
{
    use AuthorizesRequests, DispatchesJobs, ValidatesRequests;

    public function register(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'name' => 'required',
            'email' => 'required|email|unique:users,email',
            'password' => 'required|string', new Password,
            'image' => 'nullable|mimes:png,jpg,jpeg',
            'roles' => 'nullable',
            'jabatan' => 'nullable',
        ]);

        if ($validator->fails())
        {
           return ResponseFormatter::error([
            'message' => 'email ada yang sama',
            
           ], 404);
        }

        $image = Storage::putFile('public', $request->file('image'));
        
        User::create([
            'name' => $request->name,
            'email' => $request->email,
            'image' => $image,
            'roles' => $request->roles,
            'jabatan' => $request->jabatan,
            'password' => Hash::make($request->password),            
        ]);

        $user = User::where('email', $request->email)->first();

        $tokenResult = $user->createToken('authToken')->plainTextToken;

        return ResponseFormatter::success([
            'access_token' => $tokenResult,
            'token_type' => 'Bearer',
            'User' => $user
        ], 'User Registered');

    }
    public function login (Request $request)
    {
        
        $user = User::where('email', $request->email)->first();
        $tokenResult = $user->createToken('authToken')->plainTextToken;
        if ($user && Hash::check($request->password, $user->password)) {
            return ResponseFormatter::success([
                'acces_token' => $tokenResult,
                'token_type' => 'Bearer',
                'user' => $user
            ], 'Authenticated');
        }else{
            return ResponseFormatter::error([
                'message' => 'login gagal'
            ], 'Authenticated Failed', 500);
        }
    } 
    public function logout(Request $request)
    {
        $request->user()->currentAccessToken()->delete();
        return ResponseFormatter::success($request, 'Token Revoked');
    }
}
