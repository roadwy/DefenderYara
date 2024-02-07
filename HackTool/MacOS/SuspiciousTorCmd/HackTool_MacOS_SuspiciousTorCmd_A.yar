
rule HackTool_MacOS_SuspiciousTorCmd_A{
	meta:
		description = "HackTool:MacOS/SuspiciousTorCmd.A,SIGNATURE_TYPE_CMDHSTR_EXT,ffffffc8 00 0a 00 03 00 00 0a 00 "
		
	strings :
		$a_00_0 = {74 00 6f 00 72 00 69 00 66 00 79 00 } //0a 00  torify
		$a_00_1 = {74 00 6f 00 72 00 70 00 72 00 6f 00 78 00 79 00 } //0a 00  torproxy
		$a_00_2 = {69 00 6e 00 73 00 74 00 61 00 6c 00 6c 00 20 00 74 00 6f 00 72 00 } //00 00  install tor
	condition:
		any of ($a_*)
 
}