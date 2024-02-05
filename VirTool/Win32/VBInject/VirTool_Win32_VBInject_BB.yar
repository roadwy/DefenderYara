
rule VirTool_Win32_VBInject_BB{
	meta:
		description = "VirTool:Win32/VBInject.BB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 74 61 72 74 00 00 00 52 43 34 00 46 6f 72 6d 31 00 00 00 4d 6f 64 75 6c 65 32 00 50 72 6f 6a 65 63 74 31 00 } //01 00 
		$a_03_1 = {f5 00 00 00 00 59 90 01 02 f5 04 00 00 00 04 90 01 02 6c 90 01 02 f5 08 00 00 00 aa 6c 90 01 02 0a 09 00 14 00 3c 1e 6f 04 14 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}