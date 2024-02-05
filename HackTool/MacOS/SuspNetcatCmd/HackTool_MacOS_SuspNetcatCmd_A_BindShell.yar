
rule HackTool_MacOS_SuspNetcatCmd_A_BindShell{
	meta:
		description = "HackTool:MacOS/SuspNetcatCmd.A!BindShell,SIGNATURE_TYPE_CMDHSTR_EXT,ffffffc8 00 32 00 06 00 00 0a 00 "
		
	strings :
		$a_00_0 = {6d 00 6b 00 66 00 69 00 66 00 6f 00 } //1e 00 
		$a_02_1 = {6e 00 63 00 20 00 90 02 20 2d 00 6c 00 90 00 } //0a 00 
		$a_00_2 = {73 00 68 00 20 00 } //ce ff 
		$a_00_3 = {6c 00 6f 00 63 00 61 00 6c 00 68 00 6f 00 73 00 74 00 } //ce ff 
		$a_00_4 = {31 00 32 00 37 00 2e 00 30 00 2e 00 30 00 2e 00 31 00 } //ce ff 
		$a_00_5 = {30 00 2e 00 30 00 2e 00 30 00 2e 00 30 00 } //00 00 
	condition:
		any of ($a_*)
 
}