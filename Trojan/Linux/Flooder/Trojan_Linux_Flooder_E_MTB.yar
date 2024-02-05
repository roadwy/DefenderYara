
rule Trojan_Linux_Flooder_E_MTB{
	meta:
		description = "Trojan:Linux/Flooder.E!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {73 79 62 65 78 2e 63 } //01 00 
		$a_01_1 = {66 6c 6f 6f 64 70 6f 72 74 } //01 00 
		$a_01_2 = {72 61 6e 64 6f 6d 6d 65 78 69 63 6f } //01 00 
		$a_01_3 = {50 72 69 76 38 20 54 43 50 20 42 79 70 61 73 73 } //01 00 
		$a_01_4 = {53 65 6e 64 69 6e 67 20 61 74 74 61 63 6b } //00 00 
	condition:
		any of ($a_*)
 
}