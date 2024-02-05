
rule VirTool_Win32_CeeInject_AAX_bit{
	meta:
		description = "VirTool:Win32/CeeInject.AAX!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {58 50 59 03 49 3c 81 c1 90 01 04 89 0d 90 01 04 ff 15 90 00 } //01 00 
		$a_03_1 = {57 72 69 74 c7 05 90 01 04 63 65 73 73 c7 05 90 01 04 4d 65 6d 6f 90 00 } //01 00 
		$a_01_2 = {8b 0e f8 83 de fc f7 d9 8d 49 f1 c1 c9 09 d1 c1 31 d9 } //00 00 
	condition:
		any of ($a_*)
 
}