
rule HackTool_Win32_Impacketwmiexec_F{
	meta:
		description = "HackTool:Win32/Impacketwmiexec.F,SIGNATURE_TYPE_CMDHSTR_EXT,0e 00 0e 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {5c 00 63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 00 00 } //01 00 
		$a_00_1 = {20 00 2f 00 63 00 20 00 } //01 00 
		$a_00_2 = {20 00 2f 00 51 00 20 00 } //0a 00 
		$a_00_3 = {20 00 31 00 3e 00 20 00 5c 00 5c 00 31 00 32 00 37 00 2e 00 30 00 2e 00 30 00 2e 00 31 00 5c 00 41 00 44 00 4d 00 49 00 4e 00 24 00 5c 00 5f 00 5f 00 } //01 00 
		$a_00_4 = {20 00 32 00 3e 00 26 00 31 00 } //00 00 
	condition:
		any of ($a_*)
 
}