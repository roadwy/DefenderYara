
rule Trojan_Linux_Dakkatoni_P_MTB{
	meta:
		description = "Trojan:Linux/Dakkatoni.P!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_00_0 = {2f 74 6d 70 2f 2e 68 74 74 70 73 6c 6f 67 } //01 00 
		$a_00_1 = {6b 2e 63 6f 6e 65 63 74 69 6f 6e 61 70 69 73 2e 63 6f 6d } //01 00 
		$a_00_2 = {2f 65 74 63 2f 63 72 6f 6e 2e 64 2f 68 74 74 70 73 64 } //01 00 
		$a_00_3 = {2a 2f 36 20 2a 20 2a 20 2a 20 72 6f 6f 74 20 } //01 00 
		$a_00_4 = {2f 74 6d 70 2f 2e 68 74 74 70 73 70 69 64 } //01 00 
		$a_00_5 = {6b 65 79 3d 25 73 26 68 6f 73 74 5f 6e 61 6d 65 3d 25 73 26 63 70 75 5f 63 6f 75 6e 74 3d 25 64 26 6f 73 5f 74 79 70 65 3d 25 73 26 63 6f 72 65 5f 63 6f 75 6e 74 3d 25 73 } //00 00 
	condition:
		any of ($a_*)
 
}