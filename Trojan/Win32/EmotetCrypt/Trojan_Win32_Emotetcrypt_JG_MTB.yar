
rule Trojan_Win32_Emotetcrypt_JG_MTB{
	meta:
		description = "Trojan:Win32/Emotetcrypt.JG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 0a 00 "
		
	strings :
		$a_01_0 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //01 00  DllRegisterServer
		$a_01_1 = {77 21 53 6c 65 55 2b 2b 51 68 42 6d 72 46 4a 39 53 4a 5f 52 43 5e 66 4f 29 32 55 78 4e 35 4d 6c 4e 46 39 53 29 67 30 30 66 66 48 32 37 2a 69 78 45 46 4b 2a 58 26 25 4b 5e 40 65 6c 56 38 4c 74 49 25 50 43 6b 32 6f 2a 31 52 2b 63 36 2a 74 78 32 48 3e 66 31 45 33 67 76 66 75 4f 3e 2b 6d 46 37 72 6e 4e 37 5f 74 58 6a 66 78 6b 56 67 46 62 } //00 00  w!SleU++QhBmrFJ9SJ_RC^fO)2UxN5MlNF9S)g00ffH27*ixEFK*X&%K^@elV8LtI%PCk2o*1R+c6*tx2H>f1E3gvfuO>+mF7rnN7_tXjfxkVgFb
	condition:
		any of ($a_*)
 
}