
rule VirTool_Win32_CeeInject_CU{
	meta:
		description = "VirTool:Win32/CeeInject.CU,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {69 c0 f1 de 09 21 03 e8 ff d6 69 c0 a3 b1 01 45 } //01 00 
		$a_03_1 = {30 14 01 8b 35 90 01 04 8a 86 90 01 04 46 84 c0 89 35 90 01 04 75 90 01 01 33 f6 90 00 } //01 00 
		$a_03_2 = {b8 07 00 01 00 c7 05 90 01 04 44 00 00 00 a3 90 01 04 a3 90 01 04 66 81 3b 4d 5a 0f 90 01 05 8b 73 3c 8b 04 1e 03 f3 3d 50 45 00 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}