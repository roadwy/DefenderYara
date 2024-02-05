
rule VirTool_Win32_CeeInject_TD_bit{
	meta:
		description = "VirTool:Win32/CeeInject.TD!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 45 08 8a 08 32 4d 13 02 4d 13 88 08 40 89 45 08 b8 90 01 04 c3 90 00 } //01 00 
		$a_03_1 = {8b c1 8b d1 03 c6 3b fe 76 08 3b f8 0f 82 90 01 04 f7 c7 03 00 00 00 75 14 c1 e9 02 83 e2 03 83 f9 08 72 29 f3 a5 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}