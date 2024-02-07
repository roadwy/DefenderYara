
rule HackTool_Win32_Impacketwmiexec_D{
	meta:
		description = "HackTool:Win32/Impacketwmiexec.D,SIGNATURE_TYPE_CMDHSTR_EXT,0d 00 0d 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {5c 00 63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 00 00 } //01 00 
		$a_00_1 = {20 00 2f 00 63 00 20 00 } //01 00   /c 
		$a_00_2 = {20 00 2f 00 51 00 20 00 } //0a 00   /Q 
		$a_02_3 = {20 00 5c 00 5c 00 90 29 03 00 2e 00 90 29 03 00 2e 00 90 29 03 00 2e 00 90 29 03 00 5c 00 90 02 20 5c 00 90 02 20 2e 00 62 00 61 00 74 00 90 00 } //9c ff 
		$a_00_4 = {5c 00 5c 00 31 00 32 00 37 00 2e 00 30 00 2e 00 30 00 2e 00 31 00 5c 00 } //00 00  \\127.0.0.1\
	condition:
		any of ($a_*)
 
}