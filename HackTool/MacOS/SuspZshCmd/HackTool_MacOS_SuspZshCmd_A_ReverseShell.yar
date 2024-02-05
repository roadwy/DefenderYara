
rule HackTool_MacOS_SuspZshCmd_A_ReverseShell{
	meta:
		description = "HackTool:MacOS/SuspZshCmd.A!ReverseShell,SIGNATURE_TYPE_CMDHSTR_EXT,ffffffc8 00 5a 00 0a 00 00 0a 00 "
		
	strings :
		$a_00_0 = {7a 00 73 00 68 00 } //14 00 
		$a_00_1 = {7a 00 6d 00 6f 00 64 00 6c 00 6f 00 61 00 64 00 } //14 00 
		$a_00_2 = {7a 00 73 00 68 00 2f 00 6e 00 65 00 74 00 2f 00 74 00 63 00 70 00 } //14 00 
		$a_00_3 = {7a 00 74 00 63 00 70 00 } //0a 00 
		$a_00_4 = {7a 00 73 00 68 00 20 00 3e 00 26 00 } //05 00 
		$a_00_5 = {32 00 3e 00 26 00 } //05 00 
		$a_00_6 = {30 00 3e 00 26 00 } //ce ff 
		$a_00_7 = {6c 00 6f 00 63 00 61 00 6c 00 68 00 6f 00 73 00 74 00 } //ce ff 
		$a_00_8 = {31 00 32 00 37 00 2e 00 30 00 2e 00 30 00 2e 00 31 00 } //ce ff 
		$a_00_9 = {30 00 2e 00 30 00 2e 00 30 00 2e 00 30 00 } //00 00 
	condition:
		any of ($a_*)
 
}