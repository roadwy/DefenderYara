
rule VirTool_Win32_VBInject_UN{
	meta:
		description = "VirTool:Win32/VBInject.UN,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {4f 66 66 73 65 74 20 4c 6f 63 61 74 6f 72 20 56 33 20 4d 6f 64 20 42 79 20 44 72 2e 47 33 4e 49 55 53 } //01 00 
		$a_01_1 = {41 56 46 75 63 6b 65 72 20 4d 65 74 68 6f 64 } //01 00 
		$a_01_2 = {46 55 44 53 4f 6e 6c 79 2e 63 6f 6d 2e 61 72 } //01 00 
		$a_01_3 = {49 6e 64 65 74 65 63 74 61 62 6c 65 73 2e 6e 65 74 } //00 00 
	condition:
		any of ($a_*)
 
}