
rule VirTool_Win32_CeeInject_RB_bit{
	meta:
		description = "VirTool:Win32/CeeInject.RB!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b c6 33 d2 b9 0f 00 00 00 f7 f1 8a 86 90 01 04 8a 92 90 01 04 32 c2 88 86 90 01 04 46 81 fe 90 01 04 72 90 00 } //01 00 
		$a_00_1 = {32 1e 83 c6 04 88 5e 0c 8a 5e fd 32 5c 24 15 88 5e 0d 8a 5e fe 32 5c 24 16 88 5e 0e 8a 5e ff 32 d8 8b 44 24 10 88 5e 0f 40 41 } //01 00 
		$a_03_2 = {73 06 89 15 90 01 04 8b 35 90 01 04 8a 19 30 1c 30 47 41 40 4d 75 e1 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}