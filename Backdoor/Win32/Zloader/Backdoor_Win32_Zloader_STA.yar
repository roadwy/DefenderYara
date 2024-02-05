
rule Backdoor_Win32_Zloader_STA{
	meta:
		description = "Backdoor:Win32/Zloader.STA,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_80_0 = {43 61 72 72 79 2e 64 6c 6c 00 41 62 6c 65 } //Carry.dll  01 00 
		$a_01_1 = {81 c1 08 16 00 00 02 d8 8d 42 55 03 c1 88 1d be c9 18 01 69 c0 20 64 00 00 } //00 00 
		$a_00_2 = {78 } //3d 00 
	condition:
		any of ($a_*)
 
}
rule Backdoor_Win32_Zloader_STA_2{
	meta:
		description = "Backdoor:Win32/Zloader.STA,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_80_0 = {41 72 65 2e 64 6c 6c 00 53 68 65 65 74 70 6c 61 6e } //Are.dll  01 00 
		$a_01_1 = {2a c2 83 c3 13 8a d0 69 f3 48 04 01 00 c0 e0 03 02 d0 c0 e2 03 80 c2 58 } //00 00 
		$a_00_2 = {78 } //41 00 
	condition:
		any of ($a_*)
 
}
rule Backdoor_Win32_Zloader_STA_3{
	meta:
		description = "Backdoor:Win32/Zloader.STA,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_80_0 = {77 65 61 72 2e 64 6c 6c 00 4d 65 65 69 67 68 74 } //wear.dll  01 00 
		$a_01_1 = {c7 05 78 47 04 01 11 01 00 00 8d 51 b8 03 d6 69 c2 31 b4 00 00 89 15 08 48 04 01 2b c1 } //00 00 
		$a_00_2 = {78 } //42 00 
	condition:
		any of ($a_*)
 
}
rule Backdoor_Win32_Zloader_STA_4{
	meta:
		description = "Backdoor:Win32/Zloader.STA,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_80_0 = {63 72 6f 70 2e 64 6c 6c 00 42 61 6c 6c 62 72 6f 77 6e } //crop.dll  01 00 
		$a_01_1 = {ba 95 25 00 00 41 2b d1 8b c2 c1 e0 06 2b c2 03 c1 89 15 98 e0 08 10 a3 08 e0 08 10 } //00 00 
		$a_00_2 = {78 } //44 00 
	condition:
		any of ($a_*)
 
}
rule Backdoor_Win32_Zloader_STA_5{
	meta:
		description = "Backdoor:Win32/Zloader.STA,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_80_0 = {77 68 65 65 6c 2e 64 6c 6c 00 43 6f 6e 73 6f 6e 61 6e 74 71 75 6f 74 69 65 6e 74 } //wheel.dll  01 00 
		$a_01_1 = {69 ff dc d7 00 00 8b d0 2b d7 f6 2d 23 e0 08 10 a2 23 e0 08 10 } //00 00 
		$a_00_2 = {78 } //48 00 
	condition:
		any of ($a_*)
 
}
rule Backdoor_Win32_Zloader_STA_6{
	meta:
		description = "Backdoor:Win32/Zloader.STA,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_80_0 = {45 78 70 65 72 69 65 6e 63 65 2e 64 6c 6c 00 53 61 77 70 61 79 } //Experience.dll  01 00 
		$a_01_1 = {c7 05 78 47 04 01 34 01 00 00 2b cb 39 3d 90 47 04 01 72 24 8d 34 76 81 c6 9e 2f 01 00 8b c6 } //00 00 
		$a_00_2 = {78 } //49 00 
	condition:
		any of ($a_*)
 
}
rule Backdoor_Win32_Zloader_STA_7{
	meta:
		description = "Backdoor:Win32/Zloader.STA,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_80_0 = {48 6f 75 72 2e 64 6c 6c 00 4e 61 74 69 6f 6e } //Hour.dll  01 00 
		$a_01_1 = {69 c2 a1 d7 00 00 89 54 24 0c 2b c3 8a 3d 85 b9 18 01 8a 1d 83 b9 18 01 83 e8 07 80 ff 08 72 18 69 c8 a3 d7 00 00 } //00 00 
		$a_00_2 = {5d } //04 00 
	condition:
		any of ($a_*)
 
}