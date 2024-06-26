
rule HackTool_Linux_SuspUnixReShellCmd_G{
	meta:
		description = "HackTool:Linux/SuspUnixReShellCmd.G,SIGNATURE_TYPE_CMDHSTR_EXT,18 00 18 00 08 00 00 01 00 "
		
	strings :
		$a_00_0 = {70 00 66 00 5f 00 69 00 6e 00 65 00 74 00 } //01 00  pf_inet
		$a_00_1 = {73 00 6f 00 63 00 6b 00 5f 00 73 00 74 00 72 00 65 00 61 00 6d 00 } //0a 00  sock_stream
		$a_02_2 = {63 00 6f 00 6e 00 6e 00 65 00 63 00 74 00 90 02 02 28 00 90 02 50 2c 00 90 00 } //0a 00 
		$a_02_3 = {73 00 6f 00 63 00 6b 00 61 00 64 00 64 00 72 00 5f 00 69 00 6e 00 90 02 02 28 00 90 02 50 2c 00 90 00 } //01 00 
		$a_00_4 = {69 00 6e 00 65 00 74 00 5f 00 61 00 74 00 6f 00 6e 00 } //01 00  inet_aton
		$a_00_5 = {6f 00 70 00 65 00 6e 00 } //b0 ff  open
		$a_00_6 = {31 00 32 00 37 00 2e 00 30 00 2e 00 30 00 2e 00 31 00 } //b0 ff  127.0.0.1
		$a_00_7 = {30 00 2e 00 30 00 2e 00 30 00 2e 00 30 00 } //00 00  0.0.0.0
	condition:
		any of ($a_*)
 
}