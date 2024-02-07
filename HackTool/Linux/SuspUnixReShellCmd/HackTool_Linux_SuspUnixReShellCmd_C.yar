
rule HackTool_Linux_SuspUnixReShellCmd_C{
	meta:
		description = "HackTool:Linux/SuspUnixReShellCmd.C,SIGNATURE_TYPE_CMDHSTR_EXT,0f 00 0f 00 05 00 00 0a 00 "
		
	strings :
		$a_02_0 = {61 00 77 00 6b 00 20 00 42 00 45 00 47 00 49 00 4e 00 90 02 02 7b 00 90 00 } //05 00 
		$a_00_1 = {2f 00 69 00 6e 00 65 00 74 00 2f 00 74 00 63 00 70 00 2f 00 30 00 2f 00 } //05 00  /inet/tcp/0/
		$a_00_2 = {2f 00 69 00 6e 00 65 00 74 00 2f 00 75 00 64 00 70 00 2f 00 30 00 2f 00 } //ce ff  /inet/udp/0/
		$a_00_3 = {31 00 32 00 37 00 2e 00 30 00 2e 00 30 00 2e 00 31 00 } //ce ff  127.0.0.1
		$a_00_4 = {30 00 2e 00 30 00 2e 00 30 00 2e 00 30 00 } //00 00  0.0.0.0
	condition:
		any of ($a_*)
 
}