
rule VirTool_Win32_VBInject_AJG_bit{
	meta:
		description = "VirTool:Win32/VBInject.AJG!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {66 0f 7e 14 08 90 02 30 83 e9 fc 90 02 20 81 f9 90 02 20 c3 90 02 20 66 0f ef d1 90 00 } //01 00 
		$a_03_1 = {b8 00 10 40 00 90 02 30 8b 00 90 02 30 bb 00 90 02 10 5a 4d 90 02 30 0f cb 90 02 30 48 90 02 30 39 18 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}