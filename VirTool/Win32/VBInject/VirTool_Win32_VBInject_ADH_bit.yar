
rule VirTool_Win32_VBInject_ADH_bit{
	meta:
		description = "VirTool:Win32/VBInject.ADH!bit,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {b8 96 89 32 00 90 02 30 05 c0 76 0f 00 90 02 30 39 01 90 02 30 0f 90 02 30 83 e9 04 90 02 30 68 77 cc 2f 00 90 02 30 58 90 02 30 05 d6 33 23 00 90 02 30 8b 09 90 02 30 39 c1 90 02 30 0f 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}