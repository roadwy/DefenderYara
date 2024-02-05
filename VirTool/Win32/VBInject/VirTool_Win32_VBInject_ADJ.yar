
rule VirTool_Win32_VBInject_ADJ{
	meta:
		description = "VirTool:Win32/VBInject.ADJ,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {b8 fc fd fe ff } //01 00 
		$a_01_1 = {2d 04 04 04 04 } //01 00 
		$a_00_2 = {6e 6f 72 74 6f 6e } //01 00 
		$a_00_3 = {0f b7 47 14 } //01 00 
		$a_00_4 = {bb 00 00 40 00 } //01 00 
		$a_00_5 = {66 3b 77 06 } //01 00 
		$a_03_6 = {0b c0 74 02 ff e0 68 90 01 02 40 00 b8 90 01 02 40 00 ff d0 ff e0 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}