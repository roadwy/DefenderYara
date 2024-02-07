
rule PWS_Win32_OnLineGames_GZ{
	meta:
		description = "PWS:Win32/OnLineGames.GZ,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {48 6c 4d 61 69 6e 2e 64 6c 6c 00 4d 79 44 6c 6c 52 75 6e 00 53 65 72 76 69 63 65 4d 61 69 6e 00 58 69 65 5a 61 69 44 4c 4c } //01 00 
		$a_01_1 = {77 77 77 2e 78 69 61 6f 68 75 61 2e 6b 72 3a 38 30 30 31 } //01 00  www.xiaohua.kr:8001
		$a_01_2 = {4e 65 74 42 6f 74 20 41 74 74 61 63 6b 65 72 } //00 00  NetBot Attacker
	condition:
		any of ($a_*)
 
}
rule PWS_Win32_OnLineGames_GZ_2{
	meta:
		description = "PWS:Win32/OnLineGames.GZ,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 59 53 54 45 4d 33 32 5c 68 66 30 30 32 31 2e 64 6c 6c } //01 00  SYSTEM32\hf0021.dll
		$a_01_1 = {73 65 74 68 6f 6f 6b 65 20 3d 20 25 30 38 78 00 53 65 74 48 6f 6f 6b } //01 00 
		$a_01_2 = {25 73 25 73 3f 64 66 75 3d 25 73 26 64 66 70 3d 25 73 26 64 66 70 32 3d 25 73 26 64 66 6e 3d 25 73 00 00 53 45 4c 45 43 54 20 53 45 52 56 45 52 00 00 00 2e 5c 44 4e 46 2e 63 66 67 } //01 00 
		$a_01_3 = {6c 6f 67 69 6e 6e 61 6d 65 3d 64 66 00 00 00 00 26 73 74 72 50 61 73 73 77 6f 72 64 3d } //00 00 
	condition:
		any of ($a_*)
 
}