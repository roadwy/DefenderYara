
rule HackTool_Win32_Netmyone_B_dha{
	meta:
		description = "HackTool:Win32/Netmyone.B!dha,SIGNATURE_TYPE_CMDHSTR_EXT,63 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {6e 00 65 00 74 00 20 00 75 00 73 00 65 00 20 00 20 00 68 00 74 00 74 00 70 00 73 00 3a 00 2f 90 01 01 2f 00 64 00 6f 00 63 00 73 00 2e 00 6c 00 69 00 76 00 65 00 2e 00 6e 00 65 00 74 00 2f 00 90 00 } //01 00 
		$a_02_1 = {6e 00 65 00 74 00 2f 00 90 02 30 20 00 90 02 30 20 00 2f 00 75 00 3a 00 90 02 30 40 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}