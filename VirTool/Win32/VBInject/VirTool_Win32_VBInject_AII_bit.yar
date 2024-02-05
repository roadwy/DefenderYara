
rule VirTool_Win32_VBInject_AII_bit{
	meta:
		description = "VirTool:Win32/VBInject.AII!bit,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {b8 42 9e 21 00 90 02 30 05 14 62 20 00 90 02 30 39 01 90 02 30 0f 90 02 30 83 e9 04 90 02 30 68 37 53 43 00 90 02 30 58 90 02 30 05 16 ad 0f 00 90 02 30 8b 09 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}