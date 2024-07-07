
rule PWS_Win32_Lmir_gen_I{
	meta:
		description = "PWS:Win32/Lmir.gen!I,SIGNATURE_TYPE_PEHSTR,64 00 50 00 09 00 00 "
		
	strings :
		$a_01_0 = {41 63 63 65 70 74 3a 20 69 6d 61 67 65 2f 67 69 66 2c 20 69 6d 61 67 65 2f 78 2d 78 62 69 74 6d 61 70 2c 20 69 6d 61 67 65 2f 6a 70 65 67 2c 20 69 6d 61 67 65 2f 70 6a 70 65 67 2c 20 61 70 70 6c 69 63 61 74 69 6f 6e 2f 78 2d 73 68 6f 63 6b 77 61 76 65 2d 66 6c 61 73 68 2c 20 61 70 70 6c 69 63 61 74 69 6f 6e 2f 76 6e 64 2e 6d 73 2d 70 6f 77 65 72 70 6f 69 6e 74 2c 20 61 70 70 6c 69 63 61 74 69 6f 6e 2f 76 6e 64 2e 6d 73 2d 65 78 63 65 6c 2c 20 61 70 70 6c 69 63 61 74 69 6f 6e 2f 6d 73 77 6f 72 64 2c 20 2a 2f 2a } //25 Accept: image/gif, image/x-xbitmap, image/jpeg, image/pjpeg, application/x-shockwave-flash, application/vnd.ms-powerpoint, application/vnd.ms-excel, application/msword, */*
		$a_01_1 = {68 74 74 70 3a 2f 2f 6d 61 70 6c 65 73 74 6f 72 79 2e 6e 65 78 6f 6e 2e 63 6f 6d } //15 http://maplestory.nexon.com
		$a_01_2 = {57 65 62 4d 6f 64 75 6c 65 73 2f 53 69 67 6e 55 70 2f 4d 61 69 6e 4c 6f 67 69 6e 3a 74 62 45 6d 61 69 6c } //15 WebModules/SignUp/MainLogin:tbEmail
		$a_01_3 = {57 65 62 4d 6f 64 75 6c 65 73 2f 53 69 67 6e 55 70 2f 4d 61 69 6e 4c 6f 67 69 6e 3a 74 62 50 61 73 73 77 6f 72 64 } //15 WebModules/SignUp/MainLogin:tbPassword
		$a_01_4 = {63 3a 5c 31 2e 74 78 74 } //5 c:\1.txt
		$a_01_5 = {2f 50 61 67 65 73 2f 4d 79 4d 61 70 6c 65 2f 4d 6f 64 69 66 79 50 57 44 3a 74 62 50 61 73 73 77 6f 72 64 31 } //15 /Pages/MyMaple/ModifyPWD:tbPassword1
		$a_01_6 = {2f 50 61 67 65 73 2f 4d 79 4d 61 70 6c 65 2f 4d 6f 64 69 66 79 50 57 44 3a 74 62 50 61 73 73 77 6f 72 64 32 } //15 /Pages/MyMaple/ModifyPWD:tbPassword2
		$a_01_7 = {54 65 6e 63 65 6e 74 5f 54 72 61 76 65 6c 65 72 5f 4d 61 69 6e 5f 57 69 6e 64 6f 77 } //15 Tencent_Traveler_Main_Window
		$a_01_8 = {6d 61 6f 78 69 61 6e 64 61 6f 20 6d 61 70 66 69 6c 65 } //15 maoxiandao mapfile
	condition:
		((#a_01_0  & 1)*25+(#a_01_1  & 1)*15+(#a_01_2  & 1)*15+(#a_01_3  & 1)*15+(#a_01_4  & 1)*5+(#a_01_5  & 1)*15+(#a_01_6  & 1)*15+(#a_01_7  & 1)*15+(#a_01_8  & 1)*15) >=80
 
}