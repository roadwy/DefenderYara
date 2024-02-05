
rule VirTool_Win32_VBInject_TM{
	meta:
		description = "VirTool:Win32/VBInject.TM,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 02 00 "
		
	strings :
		$a_01_0 = {63 72 79 62 74 65 72 } //01 00 
		$a_01_1 = {52 74 6c 4d 6f 76 65 4d 65 6d 6f 72 79 } //03 00 
		$a_01_2 = {5c 00 63 00 72 00 79 00 62 00 74 00 65 00 72 00 2e 00 76 00 62 00 70 00 } //02 00 
		$a_01_3 = {43 00 3a 00 5c 00 55 00 73 00 65 00 72 00 73 00 5c 00 61 00 73 00 72 00 79 00 5c 00 44 00 65 00 73 00 6b 00 74 00 6f 00 70 00 5c 00 } //00 00 
	condition:
		any of ($a_*)
 
}