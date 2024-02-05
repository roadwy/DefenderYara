
rule VirTool_Win32_VBInject_AGZ_bit{
	meta:
		description = "VirTool:Win32/VBInject.AGZ!bit,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {b8 96 39 14 00 90 02 10 05 c0 c6 2d 00 90 02 10 39 41 04 75 90 02 10 68 cd 7b 34 00 90 02 10 58 90 02 10 05 80 84 1e 00 90 02 10 39 01 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule VirTool_Win32_VBInject_AGZ_bit_2{
	meta:
		description = "VirTool:Win32/VBInject.AGZ!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {64 a1 30 00 00 00 90 02 10 8b 40 0c 90 02 10 8b 40 14 90 02 10 8b 40 14 90 02 10 48 66 81 38 ff 25 75 90 01 01 e9 90 00 } //01 00 
		$a_01_1 = {40 81 38 8b 7c 24 0c 75 f7 81 78 04 85 ff 7c 08 75 ee } //01 00 
		$a_03_2 = {5f 81 34 1f 90 02 15 66 39 d3 90 02 10 75 90 02 10 ff e0 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}