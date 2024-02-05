
rule VirTool_Win32_VBInject_gen_GI{
	meta:
		description = "VirTool:Win32/VBInject.gen!GI,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {00 6d 41 6e 74 69 44 65 62 75 67 00 } //01 00 
		$a_01_1 = {00 6d 53 61 6e 64 62 6f 78 69 65 00 } //01 00 
		$a_00_2 = {55 00 73 00 65 00 72 00 73 00 5c 00 44 00 61 00 76 00 69 00 64 00 5c 00 44 00 65 00 73 00 6b 00 74 00 6f 00 70 00 5c 00 } //00 00 
	condition:
		any of ($a_*)
 
}