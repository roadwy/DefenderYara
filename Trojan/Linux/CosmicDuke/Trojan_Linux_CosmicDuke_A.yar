
rule Trojan_Linux_CosmicDuke_A{
	meta:
		description = "Trojan:Linux/CosmicDuke.A,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {4c 6f 61 64 4c 69 62 72 61 72 79 20 4c 69 62 4c 6f 63 61 74 69 6f 6e 20 26 20 22 69 6e 70 75 74 36 34 2e 64 6c 6c 22 } //01 00 
		$a_01_1 = {54 65 6d 70 4c 6f 63 61 74 69 6f 6e 20 3d 20 45 6e 76 69 72 6f 6e 28 22 74 65 6d 70 22 29 } //01 00 
		$a_01_2 = {69 6e 70 75 74 36 34 2e 64 6c 6c 22 20 41 6c 69 61 73 20 22 65 78 46 75 6e 63 22 20 28 29 } //01 00 
		$a_01_3 = {55 6e 7a 69 70 53 65 6c 66 28 28 54 65 6d 70 4c 6f 63 61 74 69 6f 6e 29 29 } //00 00 
		$a_00_4 = {5d 04 } //00 00 
	condition:
		any of ($a_*)
 
}