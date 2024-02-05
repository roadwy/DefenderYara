
rule VirTool_Win32_VBInject_AGU_bit{
	meta:
		description = "VirTool:Win32/VBInject.AGU!bit,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {0f 6e 5c 24 0c 90 02 20 0f ef d9 90 02 20 0f 7e d9 90 02 20 81 f9 00 00 04 00 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule VirTool_Win32_VBInject_AGU_bit_2{
	meta:
		description = "VirTool:Win32/VBInject.AGU!bit,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {b8 55 00 42 00 90 02 20 40 90 02 20 39 41 04 90 02 20 b8 4b 00 53 00 90 02 20 40 90 02 20 40 90 02 20 39 01 90 02 20 59 90 02 20 8b 73 10 90 02 20 89 f7 90 02 20 8b 5e 3c 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}