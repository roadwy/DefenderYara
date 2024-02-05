
rule HackTool_Linux_Prtscan_A_MTB{
	meta:
		description = "HackTool:Linux/Prtscan.A!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {73 72 63 2f 73 6d 61 63 6b 31 2e 63 } //01 00 
		$a_00_1 = {53 53 4c 5b 48 45 41 52 54 42 4c 45 45 44 5d } //01 00 
		$a_00_2 = {6d 61 73 73 63 61 6e 20 2d 2d 6e 6d 61 70 } //01 00 
		$a_00_3 = {2f 65 74 63 2f 6d 61 73 73 63 61 6e 2f 6d 61 73 73 63 61 6e 2e 63 6f 6e 66 } //01 00 
		$a_00_4 = {67 69 74 68 75 62 2e 63 6f 6d 2f 72 6f 62 65 72 74 64 61 76 69 64 67 72 61 68 61 6d 2f 6d 61 73 73 63 61 6e } //00 00 
	condition:
		any of ($a_*)
 
}