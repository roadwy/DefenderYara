
rule Trojan_Linux_HCRootkit_A{
	meta:
		description = "Trojan:Linux/HCRootkit.A,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {2f 73 62 69 6e 2f 69 6e 73 6d 6f 64 20 25 73 20 3e 20 2f 64 65 76 2f 6e 75 6c 6c 20 32 3e 26 31 } //01 00 
		$a_00_1 = {2f 62 69 6e 2f 64 6d 65 73 67 20 2d 63 20 3e 20 2f 64 65 76 2f 6e 75 6c 6c 20 32 3e 26 31 } //01 00 
		$a_00_2 = {2f 70 72 6f 63 2f 2e 69 6e 6c } //01 00 
		$a_00_3 = {2f 74 6d 70 2f 2e 74 6d 70 5f 58 58 58 58 58 58 } //00 00 
		$a_00_4 = {5d 04 00 } //00 45 
	condition:
		any of ($a_*)
 
}