
rule VirTool_Win32_VBInject_AIE_bit{
	meta:
		description = "VirTool:Win32/VBInject.AIE!bit,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {b8 7a 0a 14 00 90 02 30 05 dc f5 2d 00 90 02 30 39 01 90 02 30 0f 90 02 30 83 e9 04 90 02 30 68 3c 9f 24 00 90 02 30 58 90 02 30 05 11 61 2e 00 90 02 30 8b 09 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}