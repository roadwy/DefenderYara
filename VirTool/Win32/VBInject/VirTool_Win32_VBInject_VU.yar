
rule VirTool_Win32_VBInject_VU{
	meta:
		description = "VirTool:Win32/VBInject.VU,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {74 65 00 44 65 63 72 79 70 74 00 55 6e 70 61 63 6b 00 00 02 00 00 00 26 00 00 00 02 00 00 00 48 00 00 00 02 00 00 00 34 00 00 00 02 00 00 00 30 00 } //01 00 
		$a_01_1 = {62 79 74 49 6e 00 00 00 62 79 74 50 61 73 73 77 6f 72 64 } //00 00 
	condition:
		any of ($a_*)
 
}