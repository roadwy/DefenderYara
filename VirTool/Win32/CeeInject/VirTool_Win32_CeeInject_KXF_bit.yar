
rule VirTool_Win32_CeeInject_KXF_bit{
	meta:
		description = "VirTool:Win32/CeeInject.KXF!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {33 d2 a9 00 00 00 04 74 0a 90 02 10 81 ca 00 02 00 00 a9 00 00 00 20 74 63 90 02 20 a9 00 00 00 40 74 2c 90 00 } //01 00 
		$a_03_1 = {8b 44 24 34 0f b7 00 c1 e8 0c 83 f8 03 75 29 90 02 10 8b 44 24 04 8b 7d 00 8b d7 2b 50 34 8b 44 24 30 8b 00 03 c7 8b 4c 24 34 66 8b 09 66 81 e1 90 01 02 0f b7 c9 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}