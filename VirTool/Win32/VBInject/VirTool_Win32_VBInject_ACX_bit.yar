
rule VirTool_Win32_VBInject_ACX_bit{
	meta:
		description = "VirTool:Win32/VBInject.ACX!bit,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {b8 3e d4 30 00 90 02 30 05 18 2c 11 00 90 02 30 39 01 90 02 30 0f 90 02 30 83 e9 04 90 02 30 68 57 7e 2f 00 90 02 30 58 90 02 30 05 f6 81 23 00 90 02 30 8b 09 90 02 30 39 c1 90 02 30 0f 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}