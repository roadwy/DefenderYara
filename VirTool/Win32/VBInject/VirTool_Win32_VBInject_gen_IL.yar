
rule VirTool_Win32_VBInject_gen_IL{
	meta:
		description = "VirTool:Win32/VBInject.gen!IL,SIGNATURE_TYPE_PEHSTR_EXT,ffffffe8 03 6f 00 05 00 00 64 00 "
		
	strings :
		$a_01_0 = {53 49 4d 50 4c 45 20 41 55 54 4f 20 49 4e 4a 45 43 4b 54 4f 52 } //0a 00  SIMPLE AUTO INJECKTOR
		$a_01_1 = {43 6d 64 49 6e 6a 65 63 6b 74 6f 72 } //0a 00  CmdInjecktor
		$a_01_2 = {6d 6f 64 69 6e 6a 65 63 74 69 6f 6e } //01 00  modinjection
		$a_01_3 = {44 00 6c 00 6c 00 20 00 49 00 6e 00 6a 00 65 00 63 00 74 00 69 00 6f 00 6e 00 20 00 53 00 75 00 63 00 63 00 65 00 73 00 73 00 66 00 75 00 6c 00 21 00 } //01 00  Dll Injection Successful!
		$a_01_4 = {46 00 61 00 69 00 6c 00 65 00 64 00 20 00 74 00 6f 00 20 00 57 00 72 00 69 00 74 00 65 00 20 00 44 00 4c 00 4c 00 20 00 74 00 6f 00 20 00 50 00 72 00 6f 00 63 00 65 00 73 00 73 00 21 00 20 00 2d 00 20 00 74 00 72 00 79 00 20 00 61 00 67 00 61 00 69 00 6e 00 } //00 00  Failed to Write DLL to Process! - try again
	condition:
		any of ($a_*)
 
}