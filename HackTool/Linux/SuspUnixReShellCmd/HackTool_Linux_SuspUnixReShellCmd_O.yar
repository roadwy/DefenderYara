
rule HackTool_Linux_SuspUnixReShellCmd_O{
	meta:
		description = "HackTool:Linux/SuspUnixReShellCmd.O,SIGNATURE_TYPE_CMDHSTR_EXT,0f 00 0f 00 0a 00 00 0a 00 "
		
	strings :
		$a_02_0 = {2f 00 62 00 69 00 6e 00 2f 00 90 02 04 73 00 68 00 90 00 } //01 00 
		$a_00_1 = {73 00 68 00 20 00 2d 00 63 00 } //01 00 
		$a_01_2 = {6d 00 6b 00 66 00 69 00 66 00 6f 00 } //01 00 
		$a_01_3 = {6d 00 6b 00 6e 00 6f 00 64 00 } //01 00 
		$a_01_4 = {6e 00 63 00 } //01 00 
		$a_01_5 = {74 00 65 00 6c 00 6e 00 65 00 74 00 } //01 00 
		$a_00_6 = {32 00 3e 00 26 00 31 00 } //01 00 
		$a_00_7 = {30 00 3c 00 } //ce ff 
		$a_00_8 = {31 00 32 00 37 00 2e 00 30 00 2e 00 30 00 2e 00 31 00 } //ce ff 
		$a_00_9 = {30 00 2e 00 30 00 2e 00 30 00 2e 00 30 00 } //00 00 
	condition:
		any of ($a_*)
 
}