
rule VirTool_Win32_VBInject_AGY_bit{
	meta:
		description = "VirTool:Win32/VBInject.AGY!bit,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 44 24 08 90 02 20 85 06 74 90 02 20 8b 44 24 0c 90 02 20 39 46 04 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule VirTool_Win32_VBInject_AGY_bit_2{
	meta:
		description = "VirTool:Win32/VBInject.AGY!bit,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {68 8e c8 2d 00 90 02 20 05 c8 37 14 00 90 02 20 39 41 04 90 02 20 b8 1d ec 2d 00 90 02 20 05 30 14 25 00 90 02 20 8b 09 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}