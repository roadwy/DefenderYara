
rule VirTool_Win32_VBInject_gen_CY{
	meta:
		description = "VirTool:Win32/VBInject.gen!CY,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {4d 6f 64 75 6c 65 31 00 4d 6f 64 75 6c 65 32 00 43 6c 61 73 73 31 00 00 50 72 6f 79 65 63 74 6f 31 00 } //01 00 
		$a_01_1 = {44 65 63 72 79 70 74 46 69 6c 65 00 } //01 00 
		$a_01_2 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 00 } //00 00 
	condition:
		any of ($a_*)
 
}