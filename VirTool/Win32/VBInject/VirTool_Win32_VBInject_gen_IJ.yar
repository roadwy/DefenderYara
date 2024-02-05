
rule VirTool_Win32_VBInject_gen_IJ{
	meta:
		description = "VirTool:Win32/VBInject.gen!IJ,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {03 c2 0f 80 90 01 04 89 81 b0 00 00 00 90 00 } //01 00 
		$a_01_1 = {c7 01 07 00 01 90 } //01 00 
		$a_01_2 = {68 95 e3 35 69 } //01 00 
	condition:
		any of ($a_*)
 
}