
rule HackTool_MacOS_SuspOpensslCmd_A_ReverseShell{
	meta:
		description = "HackTool:MacOS/SuspOpensslCmd.A!ReverseShell,SIGNATURE_TYPE_CMDHSTR_EXT,ffffffc8 00 50 00 0d 00 00 0a 00 "
		
	strings :
		$a_00_0 = {6f 00 70 00 65 00 6e 00 73 00 73 00 6c 00 } //1e 00  openssl
		$a_00_1 = {73 00 5f 00 63 00 6c 00 69 00 65 00 6e 00 74 00 } //14 00  s_client
		$a_00_2 = {63 00 6f 00 6e 00 6e 00 65 00 63 00 74 00 } //05 00  connect
		$a_00_3 = {2d 00 71 00 75 00 69 00 65 00 74 00 } //0f 00  -quiet
		$a_00_4 = {73 00 68 00 20 00 } //05 00  sh 
		$a_00_5 = {32 00 3e 00 26 00 31 00 } //ce ff  2>&1
		$a_00_6 = {73 00 73 00 68 00 } //ce ff  ssh
		$a_00_7 = {2d 00 73 00 74 00 61 00 74 00 75 00 73 00 } //ce ff  -status
		$a_00_8 = {2d 00 73 00 68 00 6f 00 77 00 63 00 65 00 72 00 74 00 73 00 } //ce ff  -showcerts
		$a_00_9 = {6f 00 73 00 73 00 6c 00 74 00 65 00 73 00 74 00 } //ce ff  ossltest
		$a_00_10 = {6c 00 6f 00 63 00 61 00 6c 00 68 00 6f 00 73 00 74 00 } //ce ff  localhost
		$a_00_11 = {31 00 32 00 37 00 2e 00 30 00 2e 00 30 00 2e 00 31 00 } //ce ff  127.0.0.1
		$a_00_12 = {30 00 2e 00 30 00 2e 00 30 00 2e 00 30 00 } //00 00  0.0.0.0
	condition:
		any of ($a_*)
 
}