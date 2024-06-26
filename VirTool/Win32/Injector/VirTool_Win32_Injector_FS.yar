
rule VirTool_Win32_Injector_FS{
	meta:
		description = "VirTool:Win32/Injector.FS,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {2c 56 8b 4d 90 01 01 03 4d 90 01 01 88 01 eb 12 8b 55 90 01 01 03 55 90 01 01 8a 02 2c 98 90 00 } //01 00 
		$a_01_1 = {6c 61 75 6e 63 68 } //01 00  launch
		$a_01_2 = {70 72 6f 6d 70 74 2e 69 6e 69 } //00 00  prompt.ini
	condition:
		any of ($a_*)
 
}
rule VirTool_Win32_Injector_FS_2{
	meta:
		description = "VirTool:Win32/Injector.FS,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 04 00 00 0a 00 "
		
	strings :
		$a_03_0 = {56 4d 50 72 6f 74 65 63 74 90 02 10 00 b0 04 00 90 00 } //05 00 
		$a_01_1 = {53 65 44 65 62 75 67 50 72 69 76 69 6c 65 67 65 } //01 00  SeDebugPrivilege
		$a_01_2 = {6c 61 75 6e 63 68 00 } //01 00 
		$a_01_3 = {43 6f 6e 66 69 67 2e 69 6e 69 00 } //00 00 
		$a_00_4 = {78 5a 00 00 01 00 01 00 01 00 } //00 01 
	condition:
		any of ($a_*)
 
}
rule VirTool_Win32_Injector_FS_3{
	meta:
		description = "VirTool:Win32/Injector.FS,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {c6 45 c4 2f c6 45 c5 63 c6 45 c6 20 c6 45 c7 70 c6 45 c8 69 c6 45 c9 6e c6 45 ca 67 c6 45 cb 20 c6 45 cc 31 c6 45 cd 32 c6 45 ce 37 c6 45 cf 2e 90 02 80 c6 45 e1 33 c6 45 e2 32 c6 45 e3 2e c6 45 e4 65 c6 45 e5 78 c6 45 e6 65 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}