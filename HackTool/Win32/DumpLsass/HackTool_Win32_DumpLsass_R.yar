
rule HackTool_Win32_DumpLsass_R{
	meta:
		description = "HackTool:Win32/DumpLsass.R,SIGNATURE_TYPE_CMDHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_00_0 = {72 00 64 00 72 00 6c 00 65 00 61 00 6b 00 64 00 69 00 61 00 67 00 2e 00 65 00 78 00 65 00 } //00 00  rdrleakdiag.exe
	condition:
		any of ($a_*)
 
}