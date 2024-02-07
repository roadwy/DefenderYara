
rule PWS_Win32_Frethog_F{
	meta:
		description = "PWS:Win32/Frethog.F,SIGNATURE_TYPE_PEHSTR_EXT,22 00 22 00 09 00 00 0a 00 "
		
	strings :
		$a_02_0 = {25 73 3f 61 3d 25 73 26 73 3d 25 73 26 75 3d 25 73 26 70 3d 25 73 90 02 20 26 72 3d 25 73 26 6c 3d 25 90 03 01 01 64 73 26 6d 3d 25 90 03 01 01 64 73 90 00 } //05 00 
		$a_01_1 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //05 00  WriteProcessMemory
		$a_01_2 = {52 65 61 64 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //05 00  ReadProcessMemory
		$a_01_3 = {53 65 74 57 69 6e 64 6f 77 73 48 6f 6f 6b 45 78 41 } //05 00  SetWindowsHookExA
		$a_01_4 = {49 6e 74 65 72 6e 65 74 4f 70 65 6e 55 72 6c 41 } //02 00  InternetOpenUrlA
		$a_00_5 = {46 6f 72 74 68 67 6f 65 72 } //02 00  Forthgoer
		$a_01_6 = {53 65 44 65 62 75 67 50 72 69 76 69 6c 65 67 65 } //02 00  SeDebugPrivilege
		$a_00_7 = {67 61 6d 65 63 6c 69 65 6e 74 2e 65 78 65 } //02 00  gameclient.exe
		$a_00_8 = {73 6f 75 6c 2e 65 78 65 } //00 00  soul.exe
	condition:
		any of ($a_*)
 
}