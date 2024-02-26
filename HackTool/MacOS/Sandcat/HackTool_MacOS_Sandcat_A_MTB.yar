
rule HackTool_MacOS_Sandcat_A_MTB{
	meta:
		description = "HackTool:MacOS/Sandcat.A!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {2f 73 61 6e 64 63 61 74 2e 67 6f } //01 00  /sandcat.go
		$a_00_1 = {55 70 64 61 74 65 41 67 65 6e 74 } //01 00  UpdateAgent
		$a_00_2 = {73 65 6e 64 69 6e 67 20 70 61 79 6c 6f 61 64 } //01 00  sending payload
		$a_00_3 = {63 6c 69 65 6e 74 6b 65 79 65 78 63 68 61 6e 67 65 6d 73 67 } //00 00  clientkeyexchangemsg
	condition:
		any of ($a_*)
 
}