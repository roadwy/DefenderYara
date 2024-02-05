
rule VirTool_Win32_VBInject_AFM{
	meta:
		description = "VirTool:Win32/VBInject.AFM,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {bb c2 41 00 00 c7 00 90 01 04 53 6a 08 c7 40 04 90 01 04 ff 77 3c e8 90 00 } //01 00 
		$a_03_1 = {89 47 38 8b 07 ff 90 90 90 01 02 00 00 8b 07 57 ff 90 90 90 01 02 00 00 85 c0 7d 11 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}