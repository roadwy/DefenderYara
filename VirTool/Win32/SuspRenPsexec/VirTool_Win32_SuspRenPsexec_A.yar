
rule VirTool_Win32_SuspRenPsexec_A{
	meta:
		description = "VirTool:Win32/SuspRenPsexec.A,SIGNATURE_TYPE_CMDHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {2e 00 65 00 78 00 65 00 00 00 } //01 00 
		$a_00_1 = {2e 00 65 00 78 00 65 00 20 00 5c 00 5c 00 } //01 00 
		$a_00_2 = {20 00 2d 00 61 00 63 00 63 00 65 00 70 00 74 00 65 00 75 00 6c 00 61 00 20 00 } //01 00 
		$a_00_3 = {20 00 2d 00 73 00 20 00 } //01 00 
		$a_00_4 = {20 00 2d 00 63 00 20 00 43 00 3a 00 5c 00 } //00 00 
	condition:
		any of ($a_*)
 
}