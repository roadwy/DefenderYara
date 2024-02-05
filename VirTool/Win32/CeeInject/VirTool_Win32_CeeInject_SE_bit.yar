
rule VirTool_Win32_CeeInject_SE_bit{
	meta:
		description = "VirTool:Win32/CeeInject.SE!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 55 f8 89 15 90 01 04 c7 45 f0 90 01 04 c7 45 f0 90 01 04 8b 85 90 01 04 03 05 90 01 04 0f b6 08 89 0d 90 01 04 8b 95 90 01 04 03 15 90 01 04 a0 90 01 04 88 02 c7 45 f0 90 01 04 8b 4d f8 83 c1 01 89 4d f8 e9 90 00 } //01 00 
		$a_03_1 = {33 c2 50 8f 05 90 01 04 a1 90 01 04 8b 0d 90 01 04 89 08 8b e5 5d c3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}