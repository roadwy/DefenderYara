
rule VirTool_Win32_CeeInject_OY_bit{
	meta:
		description = "VirTool:Win32/CeeInject.OY!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {8a 14 01 30 10 40 4e 75 f7 } //01 00 
		$a_01_1 = {8a 1f 49 88 1a 42 47 85 c9 75 f5 } //01 00 
		$a_03_2 = {8a 14 16 8b ce 83 e1 90 01 01 8b c6 d2 e2 c1 f8 90 01 01 03 c7 08 10 46 3b 74 24 90 01 01 7c e2 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}