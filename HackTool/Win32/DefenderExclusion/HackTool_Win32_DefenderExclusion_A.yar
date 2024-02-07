
rule HackTool_Win32_DefenderExclusion_A{
	meta:
		description = "HackTool:Win32/DefenderExclusion.A,SIGNATURE_TYPE_CMDHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {72 00 65 00 67 00 2e 00 65 00 78 00 65 00 } //01 00  reg.exe
		$a_00_1 = {61 00 64 00 64 00 } //01 00  add
		$a_00_2 = {68 00 6b 00 6c 00 6d 00 5c 00 73 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 6d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 77 00 69 00 6e 00 64 00 6f 00 77 00 73 00 20 00 64 00 65 00 66 00 65 00 6e 00 64 00 65 00 72 00 5c 00 65 00 78 00 63 00 6c 00 75 00 73 00 69 00 6f 00 6e 00 73 00 5c 00 70 00 61 00 74 00 68 00 73 00 } //01 00  hklm\software\microsoft\windows defender\exclusions\paths
		$a_00_3 = {2f 00 66 00 20 00 2f 00 74 00 20 00 72 00 65 00 67 00 5f 00 64 00 77 00 6f 00 72 00 64 00 20 00 2f 00 76 00 } //00 00  /f /t reg_dword /v
	condition:
		any of ($a_*)
 
}