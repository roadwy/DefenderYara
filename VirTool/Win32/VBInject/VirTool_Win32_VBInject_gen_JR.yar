
rule VirTool_Win32_VBInject_gen_JR{
	meta:
		description = "VirTool:Win32/VBInject.gen!JR,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_00_0 = {36 00 00 00 59 00 6f 00 75 00 20 00 67 00 6f 00 74 00 20 00 6f 00 77 00 6e 00 65 00 64 00 20 00 62 00 79 00 20 00 44 00 45 00 20 00 74 00 65 00 61 00 6d 00 20 00 3d 00 29 00 00 00 } //01 00 
		$a_01_1 = {43 3a 5c 55 73 65 72 73 5c 73 5c 44 65 73 6b 74 6f 70 5c 44 5c 56 42 36 2e 4f 4c 42 00 } //00 00 
	condition:
		any of ($a_*)
 
}