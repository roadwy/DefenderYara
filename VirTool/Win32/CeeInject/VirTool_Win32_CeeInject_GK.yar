
rule VirTool_Win32_CeeInject_GK{
	meta:
		description = "VirTool:Win32/CeeInject.GK,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {ba ac 3d 60 00 33 c0 f0 0f b1 0a 85 c0 74 } //01 00 
		$a_01_1 = {55 48 5f 40 8b 06 46 46 89 07 46 46 83 c7 04 49 75 f2 } //01 00 
	condition:
		any of ($a_*)
 
}
rule VirTool_Win32_CeeInject_GK_2{
	meta:
		description = "VirTool:Win32/CeeInject.GK,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {f7 ef c1 fa 0a 8b c2 c1 e8 1f 8b 94 02 90 01 04 33 d1 80 fa f2 88 94 35 90 01 04 77 09 fe ca 88 94 35 90 01 04 46 81 c7 a2 0c 00 00 89 75 ec db 45 ec de 1d 90 01 04 df e0 f6 cc 41 75 b3 68 90 01 04 6a 00 8d 8d 90 01 04 ff d1 90 00 } //01 00 
	condition:
		any of ($a_*)
 
}