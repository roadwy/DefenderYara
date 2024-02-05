
rule HackTool_MacOS_Firesheep_A_MTB{
	meta:
		description = "HackTool:MacOS/Firesheep.A!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,04 00 04 00 03 00 00 02 00 "
		
	strings :
		$a_00_0 = {63 6f 6d 2e 63 6f 64 65 62 75 74 6c 65 72 2e 66 69 72 65 73 68 65 65 70 2e 62 61 63 6b 65 6e 64 } //01 00 
		$a_00_1 = {76 69 73 69 74 61 74 69 6f 6e 5f 69 6d 70 6c 5f 69 6e 76 6f 6b 65 } //01 00 
		$a_00_2 = {6f 73 78 5f 72 75 6e 5f 70 72 69 76 69 6c 65 67 65 64 3a 20 41 75 74 68 6f 72 69 7a 61 74 69 6f 6e 45 78 65 63 75 74 65 57 69 74 68 50 72 69 76 69 6c 65 67 65 73 28 29 } //00 00 
		$a_00_3 = {5d 04 00 } //00 17 
	condition:
		any of ($a_*)
 
}