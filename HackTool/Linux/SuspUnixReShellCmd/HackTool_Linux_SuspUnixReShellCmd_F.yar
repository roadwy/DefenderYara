
rule HackTool_Linux_SuspUnixReShellCmd_F{
	meta:
		description = "HackTool:Linux/SuspUnixReShellCmd.F,SIGNATURE_TYPE_CMDHSTR_EXT,0c 00 0c 00 06 00 00 0a 00 "
		
	strings :
		$a_00_0 = {3e 00 26 00 20 00 2f 00 64 00 65 00 76 00 2f 00 74 00 63 00 70 00 2f 00 } //0a 00 
		$a_00_1 = {3e 00 26 00 20 00 2f 00 64 00 65 00 76 00 2f 00 75 00 64 00 70 00 2f 00 } //01 00 
		$a_00_2 = {73 00 68 00 20 00 2d 00 69 00 } //01 00 
		$a_00_3 = {30 00 3e 00 26 00 31 00 } //ce ff 
		$a_00_4 = {31 00 32 00 37 00 2e 00 30 00 2e 00 30 00 2e 00 31 00 } //ce ff 
		$a_00_5 = {30 00 2e 00 30 00 2e 00 30 00 2e 00 30 00 } //00 00 
	condition:
		any of ($a_*)
 
}