
rule HackTool_Win32_DumpLsass_O{
	meta:
		description = "HackTool:Win32/DumpLsass.O,SIGNATURE_TYPE_CMDHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_00_0 = {70 00 72 00 6f 00 63 00 65 00 73 00 73 00 64 00 75 00 6d 00 70 00 2e 00 65 00 78 00 65 00 } //00 00 
	condition:
		any of ($a_*)
 
}