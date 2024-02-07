
rule HackTool_Linux_SuspUnixReShellCmd_L{
	meta:
		description = "HackTool:Linux/SuspUnixReShellCmd.L,SIGNATURE_TYPE_CMDHSTR_EXT,07 00 07 00 09 00 00 01 00 "
		
	strings :
		$a_00_0 = {6f 00 70 00 65 00 6e 00 73 00 73 00 6c 00 } //01 00  openssl
		$a_00_1 = {73 00 5f 00 63 00 6c 00 69 00 65 00 6e 00 74 00 } //01 00  s_client
		$a_00_2 = {2d 00 71 00 75 00 69 00 65 00 74 00 } //01 00  -quiet
		$a_00_3 = {2d 00 63 00 6f 00 6e 00 6e 00 65 00 63 00 74 00 } //01 00  -connect
		$a_00_4 = {64 00 6f 00 20 00 73 00 68 00 20 00 26 00 26 00 20 00 62 00 72 00 65 00 61 00 6b 00 3b 00 } //01 00  do sh && break;
		$a_00_5 = {64 00 6f 00 6e 00 65 00 20 00 32 00 3e 00 26 00 31 00 } //01 00  done 2>&1
		$a_00_6 = {73 00 68 00 20 00 2d 00 63 00 } //ce ff  sh -c
		$a_00_7 = {31 00 32 00 37 00 2e 00 30 00 2e 00 30 00 2e 00 31 00 } //ce ff  127.0.0.1
		$a_00_8 = {30 00 2e 00 30 00 2e 00 30 00 2e 00 30 00 } //00 00  0.0.0.0
	condition:
		any of ($a_*)
 
}