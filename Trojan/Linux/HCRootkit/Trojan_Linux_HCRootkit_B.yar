
rule Trojan_Linux_HCRootkit_B{
	meta:
		description = "Trojan:Linux/HCRootkit.B,SIGNATURE_TYPE_ELFHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {68 69 64 65 5f 70 72 6f 63 } //01 00 
		$a_00_1 = {73 5f 68 69 64 65 5f 70 69 64 73 } //01 00 
		$a_00_2 = {73 5f 69 6e 6c 5f 65 6e 74 72 79 } //01 00 
		$a_00_3 = {72 6f 6f 74 6b 69 74 } //01 00 
		$a_00_4 = {73 5f 68 69 64 65 5f 74 63 70 34 5f 70 6f 72 74 73 } //00 00 
		$a_00_5 = {5d 04 00 00 } //46 be 
	condition:
		any of ($a_*)
 
}