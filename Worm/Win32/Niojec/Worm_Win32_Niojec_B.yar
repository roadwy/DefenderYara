
rule Worm_Win32_Niojec_B{
	meta:
		description = "Worm:Win32/Niojec.B,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0e 00 06 00 00 01 00 "
		
	strings :
		$a_00_0 = {43 6e 39 31 34 5c 6d 73 69 65 78 65 63 } //01 00  Cn914\msiexec
		$a_00_1 = {53 65 42 61 63 6b 75 70 50 72 69 76 69 6c 65 67 65 } //01 00  SeBackupPrivilege
		$a_00_2 = {53 65 52 65 73 74 6f 72 65 50 72 69 76 69 6c 65 67 65 } //01 00  SeRestorePrivilege
		$a_00_3 = {53 4f 46 54 57 41 52 45 5c 50 6c 61 79 4f 6e 6c 69 6e 65 55 53 5c 49 6e 73 74 61 6c 6c 46 6f 6c 64 65 72 } //01 00  SOFTWARE\PlayOnlineUS\InstallFolder
		$a_00_4 = {44 65 6c 65 74 65 4d 65 2e 62 61 74 } //0a 00  DeleteMe.bat
		$a_01_5 = {ba 60 78 40 00 e8 77 34 00 00 6a 00 8b dc e8 c1 2d 00 00 ba 54 78 40 00 } //00 00 
	condition:
		any of ($a_*)
 
}