
rule VirTool_Win32_VBInject_gen_EO{
	meta:
		description = "VirTool:Win32/VBInject.gen!EO,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {89 81 b0 00 00 } //01 00 
		$a_03_1 = {8b 80 a4 00 00 00 90 02 0a 83 c0 08 90 00 } //01 00 
		$a_03_2 = {66 b9 ff 00 90 02 10 66 b9 d0 00 90 00 } //01 00 
		$a_01_3 = {50 68 bd ca 3b d3 } //01 00 
	condition:
		any of ($a_*)
 
}