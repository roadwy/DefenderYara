
rule VirTool_Win32_VBInject_AJS_bit{
	meta:
		description = "VirTool:Win32/VBInject.AJS!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {bb 00 10 40 00 90 02 30 8b 03 90 02 30 bb 4d 5a 90 00 } //01 00 
		$a_03_1 = {bb 00 10 40 00 90 02 30 8b 03 90 02 30 bb c0 6e 8f 00 90 02 30 81 c3 8d eb 00 00 90 00 } //01 00 
		$a_03_2 = {81 fa 41 41 41 41 75 90 0a 30 00 31 f2 90 00 } //01 00 
		$a_03_3 = {83 f9 00 0f 90 0a 30 00 8f 04 08 90 0a 30 00 31 34 24 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}