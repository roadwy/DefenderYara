
rule VirTool_Win32_ExcludeProc_A{
	meta:
		description = "VirTool:Win32/ExcludeProc.A,SIGNATURE_TYPE_CMDHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {63 00 6d 00 64 00 } //01 00 
		$a_00_1 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 } //01 00 
		$a_00_2 = {41 00 64 00 64 00 2d 00 4d 00 70 00 50 00 72 00 65 00 66 00 65 00 72 00 65 00 6e 00 63 00 65 00 20 00 2d 00 45 00 78 00 63 00 6c 00 75 00 73 00 69 00 6f 00 6e 00 50 00 72 00 6f 00 63 00 65 00 73 00 73 00 20 00 } //00 00 
	condition:
		any of ($a_*)
 
}