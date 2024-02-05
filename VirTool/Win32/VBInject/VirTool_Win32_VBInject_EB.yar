
rule VirTool_Win32_VBInject_EB{
	meta:
		description = "VirTool:Win32/VBInject.EB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_00_0 = {5c 00 50 00 6f 00 6c 00 69 00 66 00 65 00 6d 00 6f 00 20 00 45 00 62 00 72 00 69 00 6f 00 20 00 43 00 72 00 79 00 70 00 74 00 65 00 72 00 5c 00 53 00 74 00 75 00 62 00 2e 00 76 00 62 00 70 00 } //01 00 
		$a_01_1 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //00 00 
	condition:
		any of ($a_*)
 
}