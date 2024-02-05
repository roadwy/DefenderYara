
rule VirTool_Win32_VBInject_AHT_bit{
	meta:
		description = "VirTool:Win32/VBInject.AHT!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {be 4c 00 53 00 46 39 33 75 90 01 05 81 7b 04 56 00 42 00 75 90 00 } //01 00 
		$a_03_1 = {bb 55 8b ec 83 39 18 75 90 01 04 81 78 04 ec 0c 56 8d 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}