
rule VirTool_Win32_CeeInject_ABT_bit{
	meta:
		description = "VirTool:Win32/CeeInject.ABT!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {6a 00 ff 15 90 01 04 a3 90 01 04 ff 35 90 01 04 6a 00 ff 15 90 09 15 00 a1 90 01 04 05 90 01 04 a3 90 01 04 ff 35 90 00 } //01 00 
		$a_03_1 = {03 45 fc 83 65 f4 00 a3 90 01 04 81 f3 90 01 04 81 6d f4 90 01 04 81 45 f4 90 01 04 8b 4d f4 d3 e8 5b 25 90 00 } //01 00 
		$a_03_2 = {8d 14 06 e8 90 01 04 30 02 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}