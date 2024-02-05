
rule VirTool_Win32_VBInject_BAD_bit{
	meta:
		description = "VirTool:Win32/VBInject.BAD!bit,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {b8 7a 0a 14 00 90 02 20 05 dc f5 2d 00 90 02 20 39 01 0f 85 69 ff ff ff 90 02 20 83 e9 04 90 02 20 68 3c 9f 24 00 90 02 20 58 90 02 20 05 11 61 2e 00 90 02 20 8b 09 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}