
rule Trojan_Linux_SutersuRootKit_A_MTB{
	meta:
		description = "Trojan:Linux/SutersuRootKit.A!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,05 00 05 00 07 00 00 01 00 "
		
	strings :
		$a_00_0 = {2f 72 6f 6f 74 2f 65 6e 67 69 6e 65 2f 6d 79 2d 65 6e 67 69 6e 65 2f 73 61 6d 70 6c 65 2f 72 6f 6f 74 6b 69 74 2f 73 75 74 65 72 75 73 75 2d 6d 61 73 74 65 72 } //01 00 
		$a_02_1 = {6e 5f 74 63 70 90 01 01 5f 73 65 71 5f 73 68 6f 77 90 00 } //01 00 
		$a_02_2 = {6e 5f 75 64 70 90 01 01 5f 73 65 71 5f 73 68 6f 77 90 00 } //01 00 
		$a_00_3 = {6e 5f 70 72 6f 63 5f 66 69 6c 6c 64 69 72 } //01 00 
		$a_00_4 = {6e 5f 64 65 76 5f 67 65 74 5f 66 6c 61 67 73 } //01 00 
		$a_00_5 = {67 65 74 5f 74 63 70 5f 73 65 71 5f 73 68 6f 77 } //01 00 
		$a_00_6 = {2f 73 75 74 65 72 75 73 75 2e 6d 6f 64 2e 63 } //00 00 
		$a_00_7 = {5d 04 00 00 } //06 c3 
	condition:
		any of ($a_*)
 
}