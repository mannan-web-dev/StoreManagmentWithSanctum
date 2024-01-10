<?php
namespace App\Http\Controllers;
use App\Helper\JWTToken;
use App\Mail\OTPMail;
use App\Models\User;
use Exception;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Mail;
use Illuminate\View\View;



class UserController extends Controller
{

    function LoginPage():View{
        return view('pages.auth.login-page');
    }

    function RegistrationPage():View{
        return view('pages.auth.registration-page');
    }
    function SendOtpPage():View{
        return view('pages.auth.send-otp-page');
    }
    function VerifyOTPPage():View{
        return view('pages.auth.verify-otp-page');
    }

    function ResetPasswordPage():View{
        return view('pages.auth.reset-pass-page');
    }

    function ProfilePage():View{
        return view('pages.dashboard.profile-page');
    }

    //Backend system

    public function UserRegistration(Request $request){

        $request->validate([
            'firstName'=> 'required|string|max:50',
            'lastName'=> 'required|string|max:50',
            'email'=> 'required|string|max:50|unique:users,email',
            'mobile'=> 'required|string|max:50',
            'password'=> 'required|string|min:4',
        ]);
        $data = User::create([
            'firstName'=> $request->input('firstName'),
            'lastName'=> $request->input('lastName'),
            'email'=> $request->input('email'),
            'mobile'=> $request->input('mobile'),
            'password'=>Hash::make($request->input('password')),
        ]);

        try {
            return response()->json([
                "status"=>"success",
                "message"=> "User registration successfuly"
            ]);
        } catch (Exception $e) {
            return response()->json([
                "status"=>"success",
                "message"=>$e->getMessage()
            ]);
        }


    }

    public function UserLogin(Request $request){
        try {
            $request->validate([
                'email'=> 'required|string|email|max:50',
                'password'=> 'required|string|min:4',
                        ]);
    
          $user = User::where("email", $request->input("email"))->first();
    
          if(!$user || !Hash::check($request->input("password"), $user->password)){
    
            return response()->json(["status"=>"failed", "message"=> "invailled user",]);
          }
    
          $token = $user->createToken("authToken")->plainTextToken;
          return response()->json(["status"=>"success", "message"=> "Login Successfully", "token"=> $token]);
        } catch (Exception $e) {
            return response()->json(["status"=>"failed", "message"=> $e->getMessage(),]);
        }

    }

    public function UserProfile(){
       return Auth::user();
    // return Auth::user()['email'];
    }

    public function UserLogout(Request $request){
        $request->user()->tokens()->delete();
         
        return redirect('/userLogin');

    }

    public function UpdateProfile(Request $request){
              
         try {
            $request->validate([
                'firstName'=> 'required|string|max:50',
                'lastName'=> 'required|string|max:50',
                'email'=> 'required|string|email|max:50|',
                'mobile'=> 'required|string|max:50',
                // 'password'=> 'required|string|min:4',
            ]);
    
             User::where('id','=', Auth::id())->update([
                'firstName'=> $request->input('firstName'),
                'lastName'=> $request->input('lastName'),
                'email'=> $request->input('email'),
                'mobile'=> $request->input('mobile'),
                // 'password'=>Hash::make($request->input('password')),
             ]);
             return response()->json(['status'=> 'success','message'=> 'User updated']);
         } catch (Exception $e) {
                  return response()->json(['status'=> 'fail', 'message'=> $e->getMessage(),]);
         }

    }
  
    public function SendOTPCode(Request $request){

         try {
            $request->validate([
                'email'=> 'required|string|email|max:50|'
            ]);
            $email = $request->input('email');
            $otp = rand(1000, 9999);
            $count = User::where('email','=', $email)->count();
    
            if($count == 1){
                Mail::to($email)->send(new OTPMail($otp));
                User::where('email', '=', $email)->update([
                    'otp'=> $otp
                ]);

                return response()->json(['status'=> 'success','message'=> 'The OTP has been sent']);
            }else{
                return response()->json(['status'=> 'fail','message'=> 'invaild OTP code']);
            }
         } catch (Exception $e) {
         return response()->json(['status'=> 'fail', 'message'=> $e->getMessage(),]);
         }

    }

    public function VerifyOTP(Request $request){
        try {
            $request->validate([
                'email' => 'required|string|email|max:50',
                'otp' => 'required|string|min:4'
            ]);

            $email=$request->input('email');
            $otp=$request->input('otp');

            $user = User::where('email','=',$email)->where('otp','=',$otp)->first();

            if(!$user){
                return response()->json(['status' => 'fail', 'message' => 'Invalid OTP']);
            }

            // CurrentDate-UpdatedTe=4>Min

            User::where('email','=',$email)->update(['otp'=>'0']);

            $token = $user->createToken('authToken')->plainTextToken;
            return response()->json(['status' => 'success', 'message' => 'OTP Verification Successful','token'=>$token]);

        }catch (Exception $e){
            return response()->json(['status' => 'fail', 'message' => $e->getMessage()]);
        }

    }

    function ResetPassword(Request $request){

        try{
            $request->validate([
                'password' => 'required|string|min:3'
            ]);
            $id=Auth::id();
            $password=$request->input('password');
            User::where('id','=',$id)->update(['password'=>Hash::make($password)]);
            return response()->json(['status' => 'success', 'message' => 'Request Successful']);

        }catch (Exception $e){
            return response()->json(['status' => 'fail', 'message' => $e->getMessage(),]);
        }
    }
}