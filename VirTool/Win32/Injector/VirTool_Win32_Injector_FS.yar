
rule VirTool_Win32_Injector_FS{
	meta:
		description = "VirTool:Win32/Injector.FS,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {2c 56 8b 4d ?? 03 4d ?? 88 01 eb 12 8b 55 ?? 03 55 ?? 8a 02 2c 98 } //1
		$a_01_1 = {6c 61 75 6e 63 68 } //1 launch
		$a_01_2 = {70 72 6f 6d 70 74 2e 69 6e 69 } //1 prompt.ini
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
rule VirTool_Win32_Injector_FS_2{
	meta:
		description = "VirTool:Win32/Injector.FS,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 04 00 00 "
		
	strings :
		$a_03_0 = {56 4d 50 72 6f 74 65 63 74 [0-10] 00 b0 04 00 } //10
		$a_01_1 = {53 65 44 65 62 75 67 50 72 69 76 69 6c 65 67 65 } //5 SeDebugPrivilege
		$a_01_2 = {6c 61 75 6e 63 68 00 } //1
		$a_01_3 = {43 6f 6e 66 69 67 2e 69 6e 69 00 } //1
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*5+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=16
 
}
rule VirTool_Win32_Injector_FS_3{
	meta:
		description = "VirTool:Win32/Injector.FS,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {c6 45 c4 2f c6 45 c5 63 c6 45 c6 20 c6 45 c7 70 c6 45 c8 69 c6 45 c9 6e c6 45 ca 67 c6 45 cb 20 c6 45 cc 31 c6 45 cd 32 c6 45 ce 37 c6 45 cf 2e [0-80] c6 45 e1 33 c6 45 e2 32 c6 45 e3 2e c6 45 e4 65 c6 45 e5 78 c6 45 e6 65 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}