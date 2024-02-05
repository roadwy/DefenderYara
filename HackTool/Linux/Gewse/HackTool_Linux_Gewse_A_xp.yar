
rule HackTool_Linux_Gewse_A_xp{
	meta:
		description = "HackTool:Linux/Gewse.A!xp,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 04 00 00 02 00 "
		
	strings :
		$a_01_0 = {67 65 77 73 65 2e 63 } //01 00 
		$a_01_1 = {75 73 61 67 65 3a 20 25 73 20 3c 68 6f 73 74 3e 20 3c 6f 66 20 63 6f 6e 6e 65 78 3e } //01 00 
		$a_01_2 = {46 6c 6f 6f 64 69 6e 67 20 25 73 20 69 64 65 6e 74 64 20 25 64 20 74 69 6d 65 73 } //01 00 
		$a_01_3 = {4b 69 6c 6c 69 6e 67 } //00 00 
	condition:
		any of ($a_*)
 
}