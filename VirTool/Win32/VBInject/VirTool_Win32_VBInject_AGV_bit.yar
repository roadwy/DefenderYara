
rule VirTool_Win32_VBInject_AGV_bit{
	meta:
		description = "VirTool:Win32/VBInject.AGV!bit,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {0f 6e 5c 24 1c 90 02 20 0f ef d9 90 02 20 0f 7e d8 90 02 20 83 f8 00 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule VirTool_Win32_VBInject_AGV_bit_2{
	meta:
		description = "VirTool:Win32/VBInject.AGV!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {be 4b 00 53 00 90 02 10 39 33 90 02 10 81 7b 04 56 00 42 00 90 00 } //01 00 
		$a_03_1 = {68 55 8b ec 83 90 02 10 5b 90 02 10 03 04 24 90 02 10 39 18 90 02 10 81 78 04 ec 0c 56 8d 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}