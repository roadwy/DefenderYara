
rule PWS_Win32_OnLineGames_CPT{
	meta:
		description = "PWS:Win32/OnLineGames.CPT,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0b 00 05 00 00 0a 00 "
		
	strings :
		$a_02_0 = {68 74 74 70 c7 45 90 01 01 3a 2f 2f 77 c7 45 90 01 01 77 77 2e 6e c7 45 90 01 01 69 75 64 76 c7 45 90 01 01 64 2e 63 6f c7 45 90 01 01 6d 2f 78 69 c7 45 90 01 01 6e 70 6f 74 c7 45 90 01 01 69 61 6e 2f c7 45 90 01 01 6c 69 6e 2e c7 45 90 01 01 61 73 70 3f c7 45 90 01 01 61 63 3d 31 c7 45 90 01 01 26 61 3d 25 c7 45 90 01 01 73 26 73 3d 90 00 } //01 00 
		$a_01_1 = {43 72 65 61 74 65 54 6f 6f 6c 68 65 6c 70 33 32 53 6e 61 70 73 68 6f 74 } //01 00  CreateToolhelp32Snapshot
		$a_01_2 = {49 6e 74 65 72 6e 65 74 4f 70 65 6e 41 } //01 00  InternetOpenA
		$a_00_3 = {73 74 72 72 63 68 72 } //01 00  strrchr
		$a_00_4 = {53 65 74 57 69 6e 64 6f 77 73 48 6f 6f 6b 45 78 41 } //00 00  SetWindowsHookExA
	condition:
		any of ($a_*)
 
}