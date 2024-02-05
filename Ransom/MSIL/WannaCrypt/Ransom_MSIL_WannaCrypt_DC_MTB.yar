
rule Ransom_MSIL_WannaCrypt_DC_MTB{
	meta:
		description = "Ransom:MSIL/WannaCrypt.DC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_81_0 = {41 6c 6c 20 79 6f 75 72 20 66 69 6c 65 73 20 68 61 76 65 20 62 65 65 6e 20 65 6e 63 72 79 70 74 65 64 } //01 00 
		$a_81_1 = {45 6e 63 72 79 70 74 65 64 20 46 69 6c 65 73 } //01 00 
		$a_81_2 = {43 72 79 2e 69 6d 67 } //01 00 
		$a_81_3 = {40 74 6f 75 74 75 74 61 2e 63 6f 6d } //00 00 
	condition:
		any of ($a_*)
 
}