
rule VirTool_Win32_PossibleMikatz_B_cbl4{
	meta:
		description = "VirTool:Win32/PossibleMikatz.B!cbl4,SIGNATURE_TYPE_CMDHSTR_EXT,03 00 03 00 03 00 00 02 00 "
		
	strings :
		$a_00_0 = {6c 00 73 00 64 00 75 00 3a 00 3a 00 67 00 6f 00 20 00 2f 00 79 00 6e 00 6f 00 74 00 20 00 } //02 00  lsdu::go /ynot 
		$a_00_1 = {70 00 72 00 3a 00 3a 00 64 00 20 00 73 00 6c 00 73 00 61 00 3a 00 3a 00 6c 00 6f 00 70 00 20 00 } //01 00  pr::d slsa::lop 
		$a_00_2 = {20 00 71 00 75 00 69 00 74 00 } //00 00   quit
	condition:
		any of ($a_*)
 
}