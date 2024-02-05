
rule HackTool_Win32_Impacketwmiexec_E{
	meta:
		description = "HackTool:Win32/Impacketwmiexec.E,SIGNATURE_TYPE_CMDHSTR_EXT,0d 00 0d 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {5c 00 63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 00 00 } //01 00 
		$a_00_1 = {20 00 2f 00 63 00 20 00 } //0a 00 
		$a_02_2 = {3e 00 20 00 5c 00 5c 00 90 29 03 00 2e 00 90 29 03 00 2e 00 90 29 03 00 2e 00 90 29 03 00 5c 00 90 02 20 5c 00 90 02 20 2e 00 74 00 6d 00 70 00 90 00 } //01 00 
		$a_00_3 = {20 00 32 00 3e 00 26 00 31 00 } //00 00 
	condition:
		any of ($a_*)
 
}