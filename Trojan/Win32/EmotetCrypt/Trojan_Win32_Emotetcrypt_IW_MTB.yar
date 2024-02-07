
rule Trojan_Win32_Emotetcrypt_IW_MTB{
	meta:
		description = "Trojan:Win32/Emotetcrypt.IW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 05 00 00 0a 00 "
		
	strings :
		$a_01_0 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //01 00  DllRegisterServer
		$a_01_1 = {38 6e 47 41 37 6f 68 66 46 70 75 67 47 28 6c 24 21 23 32 75 5f 5f 2a 74 35 45 61 46 44 37 37 } //01 00  8nGA7ohfFpugG(l$!#2u__*t5EaFD77
		$a_01_2 = {46 4c 54 38 40 64 23 50 6d 74 6d 56 3e 77 6d 25 7a 77 78 25 4b 3e 26 2a 58 3f 5a 70 49 72 72 75 6d 6d 63 4c 76 4d 23 51 42 4c 75 6c 71 34 66 4f 4d 4f 26 49 31 4e 69 52 58 6f 57 2a 6c 26 48 6e 42 47 65 28 32 40 45 36 6b 4f 29 78 36 56 25 51 58 34 64 66 77 40 65 7a 40 3c 72 5e 5e 24 2a 6e 6d 5a 61 4b 45 5f 31 38 2a 52 4d 49 54 69 78 } //01 00  FLT8@d#PmtmV>wm%zwx%K>&*X?ZpIrrummcLvM#QBLulq4fOMO&I1NiRXoW*l&HnBGe(2@E6kO)x6V%QX4dfw@ez@<r^^$*nmZaKE_18*RMITix
		$a_01_3 = {77 21 53 6c 65 55 2b 2b 51 68 42 6d 72 46 4a 39 53 4a 5f 52 43 5e 66 4f 29 32 55 78 4e 35 4d 6c 4e 46 39 53 29 67 30 30 66 66 48 32 37 2a 69 78 45 46 4b 2a 58 26 25 4b 5e 40 65 6c 56 38 4c 74 49 25 50 43 6b 32 6f 2a 31 52 2b 63 36 2a 74 78 32 48 3e 66 31 45 33 67 76 66 75 4f 3e 2b 6d 46 37 72 6e 4e 37 5f 74 58 6a 66 78 6b 56 67 46 62 } //01 00  w!SleU++QhBmrFJ9SJ_RC^fO)2UxN5MlNF9S)g00ffH27*ixEFK*X&%K^@elV8LtI%PCk2o*1R+c6*tx2H>f1E3gvfuO>+mF7rnN7_tXjfxkVgFb
		$a_01_4 = {4e 46 2a 30 25 2a 46 26 50 59 55 35 44 25 56 39 55 39 35 49 55 55 45 55 4c 65 6b 41 45 71 33 50 75 35 52 71 73 4c 3f 74 72 58 33 6e 71 6c 6c 6f 5e 63 4f 78 34 42 2b 39 46 5a 6c 42 52 57 31 6e 79 4c 6b 64 43 73 4d 67 51 55 37 49 3e 3f 51 68 6d 6f 56 56 38 2b 46 59 29 63 47 65 6f 57 44 37 69 51 57 4b 35 50 } //00 00  NF*0%*F&PYU5D%V9U95IUUEULekAEq3Pu5RqsL?trX3nqllo^cOx4B+9FZlBRW1nyLkdCsMgQU7I>?QhmoVV8+FY)cGeoWD7iQWK5P
	condition:
		any of ($a_*)
 
}