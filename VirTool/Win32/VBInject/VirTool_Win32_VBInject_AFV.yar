
rule VirTool_Win32_VBInject_AFV{
	meta:
		description = "VirTool:Win32/VBInject.AFV,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {0f 80 2f 01 00 00 8b 90 01 01 eb d1 90 01 01 c2 41 00 00 90 01 01 6a 08 ff 90 01 01 70 e8 90 00 } //01 00 
		$a_03_1 = {b8 b8 0b 00 00 3b 90 01 01 7f 26 8b 90 01 01 c1 e0 04 03 90 01 01 44 50 e8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}