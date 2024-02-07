
rule HackTool_Win32_DumpLsass_L{
	meta:
		description = "HackTool:Win32/DumpLsass.L,SIGNATURE_TYPE_CMDHSTR_EXT,6e 00 6e 00 05 00 00 64 00 "
		
	strings :
		$a_00_0 = {73 00 71 00 6c 00 64 00 75 00 6d 00 70 00 65 00 72 00 } //0a 00  sqldumper
		$a_00_1 = {30 00 78 00 30 00 31 00 31 00 30 00 } //0a 00  0x0110
		$a_00_2 = {30 00 78 00 31 00 31 00 30 00 } //0a 00  0x110
		$a_00_3 = {30 00 78 00 31 00 31 00 30 00 30 00 } //0a 00  0x1100
		$a_00_4 = {30 00 78 00 30 00 31 00 31 00 30 00 30 00 } //00 00  0x01100
	condition:
		any of ($a_*)
 
}