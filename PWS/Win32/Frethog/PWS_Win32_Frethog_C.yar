
rule PWS_Win32_Frethog_C{
	meta:
		description = "PWS:Win32/Frethog.C,SIGNATURE_TYPE_PEHSTR_EXT,16 00 16 00 07 00 00 05 00 "
		
	strings :
		$a_00_0 = {41 56 50 2e 41 6c 65 72 74 44 69 61 6c 6f 67 } //05 00  AVP.AlertDialog
		$a_01_1 = {45 58 45 5f 57 4f 57 5f 45 58 45 } //01 00  EXE_WOW_EXE
		$a_00_2 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //05 00  SOFTWARE\Microsoft\Windows\CurrentVersion\Run
		$a_01_3 = {44 4c 4c 5f 57 4f 57 5f 44 4c 4c } //05 00  DLL_WOW_DLL
		$a_01_4 = {4a 6d 70 48 6f 6f 6b 4f 6e } //01 00  JmpHookOn
		$a_01_5 = {4a 6d 70 48 6f 6f 6b 4f 66 66 } //01 00  JmpHookOff
		$a_00_6 = {41 76 65 6e 67 65 72 20 62 79 20 4e 68 54 } //00 00  Avenger by NhT
	condition:
		any of ($a_*)
 
}