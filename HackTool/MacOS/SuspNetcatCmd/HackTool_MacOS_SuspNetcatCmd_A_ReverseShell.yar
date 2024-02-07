
rule HackTool_MacOS_SuspNetcatCmd_A_ReverseShell{
	meta:
		description = "HackTool:MacOS/SuspNetcatCmd.A!ReverseShell,SIGNATURE_TYPE_CMDHSTR_EXT,ffffffc8 00 32 00 08 00 00 0a 00 "
		
	strings :
		$a_00_0 = {6d 00 6b 00 66 00 69 00 66 00 6f 00 } //14 00  mkfifo
		$a_00_1 = {6e 00 63 00 20 00 } //0a 00  nc 
		$a_02_2 = {2f 00 62 00 69 00 6e 00 2f 00 90 02 04 73 00 68 00 90 00 } //05 00 
		$a_00_3 = {30 00 3c 00 } //0a 00  0<
		$a_00_4 = {32 00 3e 00 26 00 31 00 } //ce ff  2>&1
		$a_00_5 = {6c 00 6f 00 63 00 61 00 6c 00 68 00 6f 00 73 00 74 00 } //ce ff  localhost
		$a_00_6 = {31 00 32 00 37 00 2e 00 30 00 2e 00 30 00 2e 00 31 00 } //ce ff  127.0.0.1
		$a_00_7 = {30 00 2e 00 30 00 2e 00 30 00 2e 00 30 00 } //00 00  0.0.0.0
	condition:
		any of ($a_*)
 
}