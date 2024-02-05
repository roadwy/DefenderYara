
rule VirTool_Win32_VBInject_gen_DQ{
	meta:
		description = "VirTool:Win32/VBInject.gen!DQ,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 04 00 00 03 00 "
		
	strings :
		$a_01_0 = {e7 f5 4d 5a 00 00 c7 c3 1c } //01 00 
		$a_03_1 = {fb 12 fc 0d 6b 90 01 02 e7 6b 90 01 02 e7 08 08 00 06 90 01 01 00 a7 02 00 fd 80 90 00 } //01 00 
		$a_03_2 = {fb 12 fc 0d 04 90 01 02 fc 22 80 90 01 02 fc a0 90 00 } //03 00 
		$a_03_3 = {f5 03 00 00 00 6c 90 01 02 52 fe c1 90 01 02 40 00 00 00 90 09 08 00 fe c1 90 01 02 00 30 00 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}