
rule HackTool_Win32_DumpLsass_A{
	meta:
		description = "HackTool:Win32/DumpLsass.A,SIGNATURE_TYPE_CMDHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_00_0 = {70 00 72 00 6f 00 63 00 64 00 75 00 6d 00 70 00 } //01 00 
		$a_00_1 = {6c 00 73 00 61 00 73 00 73 00 2e 00 65 00 78 00 65 00 } //00 00 
	condition:
		any of ($a_*)
 
}