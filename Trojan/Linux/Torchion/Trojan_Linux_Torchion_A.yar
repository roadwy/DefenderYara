
rule Trojan_Linux_Torchion_A{
	meta:
		description = "Trojan:Linux/Torchion.A,SIGNATURE_TYPE_ELFHSTR_EXT,17 00 17 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {2f 65 74 63 2f 72 65 73 6f 6c 76 2e 63 6f 6e 66 } //01 00 
		$a_01_1 = {2f 65 74 63 2f 68 6f 73 74 73 } //01 00 
		$a_01_2 = {2f 65 74 63 2f 70 61 73 73 77 64 } //01 00 
		$a_01_3 = {2e 73 73 68 } //01 00 
		$a_01_4 = {2e 67 69 74 63 6f 6e 66 69 67 } //0a 00 
		$a_01_5 = {67 65 74 4e 61 6d 65 73 65 72 76 65 72 73 } //0a 00 
		$a_01_6 = {67 61 74 68 65 72 46 69 6c 65 73 } //00 00 
	condition:
		any of ($a_*)
 
}