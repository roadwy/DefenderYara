
rule VirTool_Win32_Vanti_B{
	meta:
		description = "VirTool:Win32/Vanti.B,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 02 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {81 c3 00 00 01 00 90 02 40 90 03 06 03 81 fb 00 00 00 80 83 f9 00 90 02 50 75 90 02 50 66 81 38 50 45 90 02 50 81 3a 4b 45 52 4e 90 00 } //01 00 
		$a_01_1 = {8b 4c 24 2c 8b 74 24 14 51 6a 01 53 8d 14 1e ff d2 8b c6 } //01 00 
		$a_00_2 = {43 3a 5c 57 49 4e 44 4f 57 53 5c 53 59 53 54 45 4d 33 32 5c 64 72 69 76 65 72 73 5c 6e 74 66 73 2e 73 79 73 } //02 00  C:\WINDOWS\SYSTEM32\drivers\ntfs.sys
		$a_03_3 = {68 5c 64 72 69 e8 90 01 02 00 00 8f 02 e8 90 02 30 68 76 65 72 73 e8 90 02 50 68 6e 74 66 73 e8 90 02 30 68 2e 73 79 73 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}