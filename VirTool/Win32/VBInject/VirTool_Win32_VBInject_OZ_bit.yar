
rule VirTool_Win32_VBInject_OZ_bit{
	meta:
		description = "VirTool:Win32/VBInject.OZ!bit,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {64 a1 30 00 00 00 90 02 20 8b 40 0c 90 02 20 8b 40 14 90 02 20 8b 00 90 02 20 8b 58 28 90 02 20 81 3b 4d 00 53 00 75 90 02 20 81 7b 04 56 00 42 00 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule VirTool_Win32_VBInject_OZ_bit_2{
	meta:
		description = "VirTool:Win32/VBInject.OZ!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {64 ff 35 30 00 00 00 90 02 30 58 90 02 30 8b 40 0c 90 02 30 8b 40 14 90 02 30 8b 00 90 02 30 8b 58 28 90 02 30 81 7b 04 56 00 42 00 90 00 } //02 00 
		$a_03_1 = {83 f8 00 75 90 02 30 89 e1 90 02 30 83 c1 30 90 02 30 89 ca 90 02 30 83 c2 14 90 02 30 e8 90 02 30 89 e2 90 02 30 6a 00 90 02 30 8b 1a 90 02 30 81 eb 00 10 00 00 90 02 30 53 90 02 30 6a 00 90 02 30 6a 00 90 02 30 ff 72 68 90 02 30 ff 72 6c 90 02 30 ff 72 70 90 02 30 ff 72 74 90 00 } //02 00 
		$a_03_2 = {3b 54 24 10 75 90 02 30 b9 90 02 30 83 e9 04 90 02 30 ff 34 0f 90 02 30 5a 90 02 30 e8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}