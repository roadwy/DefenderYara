
rule VirTool_Win32_SuspSchtasksCreate_A{
	meta:
		description = "VirTool:Win32/SuspSchtasksCreate.A,SIGNATURE_TYPE_CMDHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_02_0 = {73 00 63 00 68 00 74 00 61 00 73 00 6b 00 73 00 90 02 08 20 00 2f 00 63 00 72 00 65 00 61 00 74 00 65 00 20 00 90 00 } //01 00 
		$a_02_1 = {20 00 2f 00 52 00 55 00 20 00 90 02 08 53 00 59 00 53 00 54 00 45 00 4d 00 20 00 90 00 } //01 00 
		$a_02_2 = {20 00 2f 00 54 00 52 00 20 00 90 02 08 70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}