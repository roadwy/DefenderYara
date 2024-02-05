
rule HackTool_Linux_Moonwalk_A_MTB{
	meta:
		description = "HackTool:Linux/Moonwalk.A!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {4d 4f 4f 4e 57 41 4c 4b } //01 00 
		$a_01_1 = {62 69 6e 2f 74 6f 75 63 68 2d 74 2d 6d 2d 61 2f 2e 4d 4f 4f 4e 57 41 4c 4b } //01 00 
		$a_01_2 = {2f 66 69 6e 64 2d 6d 61 78 64 65 70 74 68 33 2d 74 79 70 65 64 2d 70 65 72 6d 2d 37 37 37 73 72 63 2f 63 6f 72 65 2f 72 65 63 6f 6e 2e 72 73 2e 4d 4f 4f 4e 57 41 4c 4b } //01 00 
		$a_01_3 = {73 72 63 2f 63 6f 72 65 2f 6c 6f 67 67 65 72 2e 72 73 } //01 00 
		$a_01_4 = {2f 76 61 72 2f 6c 6f 67 2f 75 74 6d 70 2f 76 61 72 2f 6c 6f 67 2f 77 74 6d 70 2f 76 61 72 2f 6c 6f 67 2f 73 79 73 74 65 6d 2e 6c 6f 67 } //00 00 
	condition:
		any of ($a_*)
 
}