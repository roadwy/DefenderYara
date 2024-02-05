
rule VirTool_Win32_CeeInject_UB_bit{
	meta:
		description = "VirTool:Win32/CeeInject.UB!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {8d 45 f8 50 6a 40 68 90 01 04 8b 45 08 50 ff 15 90 00 } //01 00 
		$a_03_1 = {33 c0 89 45 90 01 01 8b 45 90 01 01 03 45 90 01 01 8a 00 88 45 90 02 10 8b 45 90 01 01 89 45 90 02 10 80 75 90 02 10 8b 45 90 01 01 03 45 90 01 01 8a 55 90 01 01 88 10 90 00 } //01 00 
		$a_01_2 = {8b 45 08 05 df 1e 00 00 89 45 fc } //00 00 
	condition:
		any of ($a_*)
 
}