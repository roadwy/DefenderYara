
rule HackTool_Linux_SuspUnixReShellCmd_I{
	meta:
		description = "HackTool:Linux/SuspUnixReShellCmd.I,SIGNATURE_TYPE_CMDHSTR_EXT,0f 00 0f 00 08 00 00 02 00 "
		
	strings :
		$a_02_0 = {3c 00 3e 00 90 02 02 2f 00 64 00 65 00 76 00 2f 00 74 00 63 00 70 00 2f 00 90 00 } //02 00 
		$a_02_1 = {3c 00 3e 00 90 02 02 2f 00 64 00 65 00 76 00 2f 00 75 00 64 00 70 00 2f 00 90 00 } //0a 00 
		$a_00_2 = {73 00 68 00 20 00 2d 00 63 00 } //01 00  sh -c
		$a_00_3 = {65 00 78 00 65 00 63 00 } //01 00  exec
		$a_00_4 = {3c 00 26 00 } //01 00  <&
		$a_00_5 = {3e 00 26 00 } //ce ff  >&
		$a_00_6 = {31 00 32 00 37 00 2e 00 30 00 2e 00 30 00 2e 00 31 00 } //ce ff  127.0.0.1
		$a_00_7 = {30 00 2e 00 30 00 2e 00 30 00 2e 00 30 00 } //00 00  0.0.0.0
	condition:
		any of ($a_*)
 
}