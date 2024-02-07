
rule HackTool_Win32_DumpLsass_P{
	meta:
		description = "HackTool:Win32/DumpLsass.P,SIGNATURE_TYPE_CMDHSTR_EXT,0a 00 0a 00 02 00 00 0a 00 "
		
	strings :
		$a_00_0 = {44 00 75 00 6d 00 70 00 4d 00 69 00 6e 00 69 00 74 00 6f 00 6f 00 6c 00 2e 00 65 00 78 00 65 00 } //0a 00  DumpMinitool.exe
		$a_00_1 = {2d 00 70 00 72 00 6f 00 63 00 65 00 73 00 73 00 49 00 64 00 } //00 00  -processId
	condition:
		any of ($a_*)
 
}