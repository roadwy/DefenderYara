
rule HackTool_MacOS_ZapTool_A_MTB{
	meta:
		description = "HackTool:MacOS/ZapTool.A!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {4d 61 73 73 43 6f 6e 6e 65 63 74 6f 72 43 6f 6e 74 72 6f 6c 6c 65 72 20 62 65 67 69 6e 41 74 74 61 63 6b 3a } //01 00 
		$a_00_1 = {73 65 6e 64 44 61 74 61 } //01 00 
		$a_00_2 = {2f 48 61 63 6b 69 6e 67 2f 4d 79 20 50 72 6f 67 72 61 6d 73 2f 53 6f 75 72 63 65 2f 43 6f 63 6f 61 2f 5a 61 70 41 74 74 61 63 6b 2f } //01 00 
		$a_00_3 = {55 44 50 46 6c 6f 6f 64 65 72 43 6f 6e 74 72 6f 6c 6c 65 72 2e 68 } //00 00 
	condition:
		any of ($a_*)
 
}