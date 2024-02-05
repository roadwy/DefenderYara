
rule VirTool_Win32_CeeInject_CK{
	meta:
		description = "VirTool:Win32/CeeInject.CK,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 45 0c 48 48 0f 84 90 01 02 00 00 83 e8 0d 0f 84 90 01 02 00 00 2d 02 01 00 00 74 30 e8 90 00 } //01 00 
		$a_03_1 = {35 01 01 74 c6 05 90 01 02 01 01 74 c6 05 90 01 02 01 01 6f c6 05 90 01 02 01 01 61 90 00 } //01 00 
		$a_03_2 = {01 01 0f b6 08 2b 0d 90 01 02 01 01 74 1e ff 05 90 01 02 01 01 81 3d 90 01 02 01 01 8b 00 00 00 90 00 } //01 00 
		$a_01_3 = {83 ec 10 c7 45 f0 01 00 00 00 c7 45 f4 01 00 00 00 c7 45 f8 02 00 00 00 c7 45 fc b8 0b 00 00 } //01 00 
		$a_03_4 = {68 00 7f 00 00 6a 00 89 45 e8 ff 15 90 01 02 01 01 6a 6c 89 45 ec ff 75 e4 c7 45 f0 06 00 00 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}