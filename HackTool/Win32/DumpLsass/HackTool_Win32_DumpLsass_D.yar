
rule HackTool_Win32_DumpLsass_D{
	meta:
		description = "HackTool:Win32/DumpLsass.D,SIGNATURE_TYPE_CMDHSTR_EXT,1e 00 1e 00 03 00 00 0a 00 "
		
	strings :
		$a_00_0 = {2d 00 64 00 75 00 6d 00 70 00 54 00 79 00 70 00 65 00 20 00 46 00 75 00 6c 00 6c 00 } //0a 00  -dumpType Full
		$a_00_1 = {2d 00 70 00 72 00 6f 00 63 00 65 00 73 00 73 00 49 00 64 00 } //0a 00  -processId
		$a_00_2 = {2d 00 66 00 69 00 6c 00 65 00 } //00 00  -file
	condition:
		any of ($a_*)
 
}