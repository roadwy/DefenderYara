
rule VirTool_Win32_VBInject_OS_bit{
	meta:
		description = "VirTool:Win32/VBInject.OS!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 02 00 "
		
	strings :
		$a_03_0 = {64 8b 0d 18 00 00 00 90 02 40 8b 49 30 90 02 40 02 51 02 90 02 40 ff e2 90 00 } //01 00 
		$a_03_1 = {8b 43 2c eb 90 02 40 0f 6e e0 90 02 40 0f ef e6 90 02 40 0f 7e e0 90 02 40 83 f8 00 0f 85 90 00 } //00 00 
		$a_00_2 = {78 5a } //00 00 
	condition:
		any of ($a_*)
 
}
rule VirTool_Win32_VBInject_OS_bit_2{
	meta:
		description = "VirTool:Win32/VBInject.OS!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {64 ff 35 30 00 00 00 90 02 30 58 90 02 30 8b 40 0c 90 02 30 8b 40 14 90 00 } //02 00 
		$a_03_1 = {81 3b 4d 00 53 00 75 90 02 30 81 7b 04 56 00 42 00 75 90 02 30 8b 70 10 90 02 30 8b 5e 3c 90 02 30 01 de 90 02 30 90 02 30 8b 5e 78 90 00 } //00 00 
		$a_00_2 = {5d 04 } //00 00 
	condition:
		any of ($a_*)
 
}