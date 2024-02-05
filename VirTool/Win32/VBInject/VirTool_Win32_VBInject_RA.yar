
rule VirTool_Win32_VBInject_RA{
	meta:
		description = "VirTool:Win32/VBInject.RA,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {57 51 53 ff 52 2c 3b c6 db e2 7d } //01 00 
		$a_02_1 = {42 00 6f 00 74 00 65 00 6c 00 6c 00 5c 00 90 02 40 42 00 6f 00 74 00 90 02 20 2e 00 76 00 62 00 70 00 90 00 } //01 00 
		$a_00_2 = {42 00 6f 00 74 00 65 00 6c 00 6c 00 61 00 42 00 6f 00 20 00 74 00 65 00 6c 00 6c 00 2e 00 73 00 63 00 72 00 } //00 00 
	condition:
		any of ($a_*)
 
}