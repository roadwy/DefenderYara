
rule Trojan_Win32_Emotet_CD_MTB{
	meta:
		description = "Trojan:Win32/Emotet.CD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 02 00 00 0a 00 "
		
	strings :
		$a_00_0 = {83 ec 1c 8b 45 08 89 45 f8 8b 45 0c 89 45 fc 8b 45 fc 8b 00 89 45 f4 8b 45 f8 8b 00 89 45 f0 8b 45 f0 8a 00 88 45 ef } //05 00 
		$a_81_1 = {77 21 53 6c 65 55 2b 2b 51 68 42 6d 72 46 4a 39 53 4a 5f 52 43 5e 66 4f 29 32 55 78 4e 35 4d 6c 4e 46 39 53 29 67 30 30 66 66 48 32 37 2a 69 78 45 46 4b 2a 58 26 25 4b 5e 40 65 6c 56 38 4c 74 49 25 50 43 6b 32 6f 2a 31 52 2b 63 36 2a 74 78 32 48 } //00 00  w!SleU++QhBmrFJ9SJ_RC^fO)2UxN5MlNF9S)g00ffH27*ixEFK*X&%K^@elV8LtI%PCk2o*1R+c6*tx2H
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Emotet_CD_MTB_2{
	meta:
		description = "Trojan:Win32/Emotet.CD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 05 00 00 03 00 "
		
	strings :
		$a_81_0 = {2a 57 49 4d 51 56 2a 34 56 37 73 69 23 61 48 78 3f 24 73 28 24 6d 55 7a 21 6b 2a 65 58 28 29 49 35 5a 34 23 24 6f 3c 69 28 6f 5a 64 48 41 66 45 34 6d 7a 53 3c 31 25 40 4e 40 4e 47 59 35 57 5e 32 62 59 59 56 56 70 29 } //03 00  *WIMQV*4V7si#aHx?$s($mUz!k*eX()I5Z4#$o<i(oZdHAfE4mzS<1%@N@NGY5W^2bYYVVp)
		$a_81_1 = {52 65 73 74 72 69 63 74 52 75 6e } //03 00  RestrictRun
		$a_81_2 = {4e 6f 44 72 69 76 65 73 } //03 00  NoDrives
		$a_81_3 = {4f 74 68 65 72 2e 64 6c 6c } //03 00  Other.dll
		$a_81_4 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //00 00  DllRegisterServer
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Emotet_CD_MTB_3{
	meta:
		description = "Trojan:Win32/Emotet.CD!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 44 24 14 8a 5c 24 17 8a d4 8a c8 c0 ea 04 c0 e1 02 0a d1 8a 4c 24 16 88 16 8a d1 8a c4 46 c0 ea 02 c0 e0 04 0a d0 8b 44 24 10 88 16 46 c0 e1 06 0a cb 33 d2 88 0e 46 85 c0 } //01 00 
		$a_01_1 = {6a 40 68 00 10 00 00 50 6a 00 ff 54 24 2c 8b 4c 24 58 8b 54 24 54 8b f0 51 52 56 ff 54 24 48 8b 44 24 64 8b 54 24 24 83 c4 0c 8d 4c 24 58 50 51 56 6a 00 6a 01 6a 00 52 ff 54 24 5c } //00 00 
	condition:
		any of ($a_*)
 
}