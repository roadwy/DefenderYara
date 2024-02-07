
rule HackTool_MacOS_SuspSocatCmd_A_BindShell{
	meta:
		description = "HackTool:MacOS/SuspSocatCmd.A!BindShell,SIGNATURE_TYPE_CMDHSTR_EXT,ffffffc8 00 29 00 09 00 00 0a 00 "
		
	strings :
		$a_00_0 = {73 00 6f 00 63 00 61 00 74 00 } //14 00  socat
		$a_00_1 = {65 00 78 00 65 00 63 00 3a 00 } //05 00  exec:
		$a_00_2 = {62 00 61 00 73 00 68 00 } //05 00  bash
		$a_00_3 = {70 00 74 00 79 00 } //01 00  pty
		$a_00_4 = {74 00 63 00 70 00 2d 00 6c 00 69 00 73 00 74 00 65 00 6e 00 3a 00 } //01 00  tcp-listen:
		$a_00_5 = {75 00 64 00 70 00 2d 00 6c 00 69 00 73 00 74 00 65 00 6e 00 3a 00 } //ce ff  udp-listen:
		$a_00_6 = {6c 00 6f 00 63 00 61 00 6c 00 68 00 6f 00 73 00 74 00 } //ce ff  localhost
		$a_00_7 = {31 00 32 00 37 00 2e 00 30 00 2e 00 30 00 2e 00 31 00 } //ce ff  127.0.0.1
		$a_00_8 = {30 00 2e 00 30 00 2e 00 30 00 2e 00 30 00 } //00 00  0.0.0.0
	condition:
		any of ($a_*)
 
}