
rule VirTool_Win32_CeeInject_MN_bit{
	meta:
		description = "VirTool:Win32/CeeInject.MN!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {32 c8 88 82 90 01 04 32 0d 90 01 04 8a 82 90 01 04 32 c1 88 8a 90 01 04 32 05 90 01 04 8a 8a 90 01 04 32 c8 88 82 90 01 04 32 0d 90 01 04 8a 82 90 01 04 32 c1 88 8a 90 01 04 32 05 90 01 04 88 82 90 00 } //01 00 
		$a_01_1 = {8a 81 0f e3 41 00 32 05 10 e3 41 00 30 81 10 e3 41 00 41 83 f9 12 72 e8 } //01 00 
		$a_03_2 = {56 57 8d 45 f1 50 ff 15 90 01 04 8b 35 90 01 04 8b f8 6a 73 57 ff d6 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}