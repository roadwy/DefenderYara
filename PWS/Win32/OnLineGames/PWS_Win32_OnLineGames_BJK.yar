
rule PWS_Win32_OnLineGames_BJK{
	meta:
		description = "PWS:Win32/OnLineGames.BJK,SIGNATURE_TYPE_PEHSTR,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {49 6e 74 65 72 6e 65 74 4f 70 65 6e 55 72 6c } //1 InternetOpenUrl
		$a_01_1 = {43 61 6c 6c 4e 65 78 74 48 6f 6f 6b 45 78 } //1 CallNextHookEx
		$a_01_2 = {47 65 74 4b 65 79 53 74 61 74 65 } //1 GetKeyState
		$a_01_3 = {53 65 6e 64 47 61 6d 65 44 61 74 61 } //1 SendGameData
		$a_01_4 = {35 36 32 34 35 32 46 2d 46 41 33 36 2d 42 41 34 46 2d 38 39 32 41 2d 46 46 35 46 42 42 41 43 35 33 31 } //1 562452F-FA36-BA4F-892A-FF5FBBAC531
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}