
rule HackTool_Linux_Bscan_A_xp{
	meta:
		description = "HackTool:Linux/Bscan.A!xp,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {73 74 61 72 74 69 6e 67 20 62 73 63 61 6e } //01 00 
		$a_01_1 = {42 53 43 41 4e 20 45 58 49 54 49 4e 47 20 4f 4e 20 53 49 47 4e 41 4c 20 25 64 } //01 00 
		$a_01_2 = {6f 75 74 70 75 74 20 2d 3e 20 25 73 2e 62 73 63 61 6e 25 73 } //01 00 
		$a_01_3 = {62 73 63 61 6e 20 66 6f 72 6b 65 64 } //00 00 
	condition:
		any of ($a_*)
 
}