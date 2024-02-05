
rule HackTool_Linux_SuspUnixReShellCmd_M{
	meta:
		description = "HackTool:Linux/SuspUnixReShellCmd.M,SIGNATURE_TYPE_CMDHSTR_EXT,04 00 04 00 06 00 00 01 00 "
		
	strings :
		$a_00_0 = {74 00 65 00 6c 00 6e 00 65 00 74 00 } //01 00 
		$a_00_1 = {64 00 6f 00 20 00 73 00 68 00 20 00 26 00 26 00 20 00 62 00 72 00 65 00 61 00 6b 00 3b 00 } //01 00 
		$a_00_2 = {64 00 6f 00 6e 00 65 00 20 00 32 00 3e 00 26 00 31 00 } //01 00 
		$a_00_3 = {73 00 68 00 20 00 2d 00 63 00 } //ce ff 
		$a_00_4 = {31 00 32 00 37 00 2e 00 30 00 2e 00 30 00 2e 00 31 00 } //ce ff 
		$a_00_5 = {30 00 2e 00 30 00 2e 00 30 00 2e 00 30 00 } //00 00 
	condition:
		any of ($a_*)
 
}