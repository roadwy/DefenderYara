
rule HackTool_Linux_Sitpara_A_xp{
	meta:
		description = "HackTool:Linux/Sitpara.A!xp,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 79 6e 74 61 78 3a 20 25 73 20 5b 2d 64 66 6c 73 53 54 62 76 44 46 50 52 5d 20 5b 2d 70 20 70 65 72 63 65 6e 74 5d 20 5b 2d 6d 20 4d 41 43 5d 20 49 4e 54 45 52 46 41 43 45 } //01 00 
		$a_01_1 = {6b 69 6c 6c 65 64 20 66 6c 6f 6f 64 69 6e 67 } //01 00 
		$a_01_2 = {64 66 6c 6d 3a 73 76 44 46 70 3a 50 52 53 3a 54 3a 62 } //01 00 
		$a_01_3 = {63 6f 6e 73 74 61 6e 74 6c 79 20 66 6c 6f 6f 64 } //00 00 
	condition:
		any of ($a_*)
 
}