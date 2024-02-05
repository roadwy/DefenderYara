
rule VirTool_Win32_VBInject_gen_LA{
	meta:
		description = "VirTool:Win32/VBInject.gen!LA,SIGNATURE_TYPE_PEHSTR_EXT,04 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {b8 ab 76 1a 74 f7 d8 b9 ba f7 7c 3f 83 d1 00 f7 d9 } //01 00 
		$a_01_1 = {c7 40 08 08 8b 00 31 c7 40 0c c9 3b 4d 0c } //01 00 
		$a_01_2 = {c7 04 01 74 02 8b 00 c7 44 01 04 c9 c3 00 00 } //00 00 
	condition:
		any of ($a_*)
 
}