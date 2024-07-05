
rule HackTool_Linux_SuspUnixReShellCmd_K{
	meta:
		description = "HackTool:Linux/SuspUnixReShellCmd.K,SIGNATURE_TYPE_CMDHSTR_EXT,1c 00 1c 00 0b 00 00 05 00 "
		
	strings :
		$a_00_0 = {6c 00 75 00 61 00 } //05 00  lua
		$a_00_1 = {73 00 6f 00 63 00 6b 00 65 00 74 00 } //05 00  socket
		$a_00_2 = {63 00 6f 00 6e 00 6e 00 65 00 63 00 74 00 } //05 00  connect
		$a_00_3 = {72 00 65 00 63 00 65 00 69 00 76 00 65 00 } //05 00  receive
		$a_02_4 = {69 00 6f 00 90 02 02 2e 00 90 02 02 70 00 6f 00 70 00 65 00 6e 00 90 00 } //01 00 
		$a_00_5 = {73 00 65 00 6e 00 64 00 } //01 00  send
		$a_00_6 = {63 00 6c 00 6f 00 73 00 65 00 } //01 00  close
		$a_00_7 = {2d 00 65 00 } //c4 ff  -e
		$a_00_8 = {31 00 32 00 37 00 2e 00 30 00 2e 00 30 00 2e 00 31 00 } //c4 ff  127.0.0.1
		$a_00_9 = {6c 00 6f 00 63 00 61 00 6c 00 68 00 6f 00 73 00 74 00 } //c4 ff  localhost
		$a_00_10 = {30 00 2e 00 30 00 2e 00 30 00 2e 00 30 00 } //00 00  0.0.0.0
	condition:
		any of ($a_*)
 
}