
rule VirTool_Win32_CeeInject_gen_FD{
	meta:
		description = "VirTool:Win32/CeeInject.gen!FD,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_09_0 = {35 34 41 33 38 31 38 46 2d 32 38 41 37 2d 34 35 32 35 2d 42 32 44 45 2d 39 36 45 37 38 31 37 34 41 42 36 35 } //01 00 
		$a_00_1 = {33 8b f7 8a 8b 0f 03 0f 03 23 8b 89 03 8a 88 47 88 } //01 00 
		$a_02_2 = {c7 45 f0 01 00 00 00 66 8b 04 75 90 01 04 66 33 04 75 90 01 04 56 8b cb 0f b7 f8 e8 90 01 03 ff 46 66 89 38 83 fe 0c 72 90 00 } //01 00 
		$a_02_3 = {c7 45 f0 01 00 00 00 8a 9e 90 01 04 32 9e 90 01 04 56 8b cf e8 90 01 03 ff 46 88 18 83 fe 14 72 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}