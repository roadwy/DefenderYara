
rule VirTool_Win32_PossibleMikatz_A_cbl4{
	meta:
		description = "VirTool:Win32/PossibleMikatz.A!cbl4,SIGNATURE_TYPE_CMDHSTR_EXT,08 00 08 00 08 00 00 01 00 "
		
	strings :
		$a_00_0 = {70 00 72 00 3a 00 3a 00 64 00 } //01 00  pr::d
		$a_00_1 = {73 00 6c 00 73 00 61 00 3a 00 3a 00 68 00 74 00 70 00 20 00 2f 00 75 00 73 00 65 00 72 00 3a 00 } //01 00  slsa::htp /user:
		$a_00_2 = {20 00 2f 00 6e 00 74 00 6c 00 6d 00 3a 00 } //01 00   /ntlm:
		$a_00_3 = {20 00 2f 00 64 00 6f 00 6d 00 61 00 69 00 6e 00 3a 00 } //01 00   /domain:
		$a_00_4 = {20 00 2f 00 72 00 65 00 6d 00 6f 00 74 00 65 00 70 00 63 00 3a 00 } //01 00   /remotepc:
		$a_00_5 = {20 00 2f 00 70 00 65 00 78 00 65 00 3a 00 } //01 00   /pexe:
		$a_00_6 = {20 00 2f 00 73 00 79 00 73 00 3a 00 } //01 00   /sys:
		$a_00_7 = {20 00 2f 00 70 00 72 00 75 00 6e 00 3a 00 } //00 00   /prun:
	condition:
		any of ($a_*)
 
}