
rule Ransom_MSIL_KawaiiCrypt_ST_MTB{
	meta:
		description = "Ransom:MSIL/KawaiiCrypt.ST!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_81_0 = {62 63 31 71 63 71 72 35 66 66 72 34 66 71 64 33 61 38 65 39 6a 76 36 64 77 66 6b 6d 35 34 70 35 7a 75 34 33 6d 70 36 39 76 73 } //01 00 
		$a_81_1 = {4b 41 57 41 49 49 20 72 61 6e 73 6f 6d 77 61 72 65 } //01 00 
		$a_81_2 = {68 61 76 65 20 62 65 65 6e 20 65 6e 63 72 79 70 74 65 64 } //01 00 
		$a_81_3 = {64 65 63 72 79 70 74 69 6f 6e 20 6b 65 79 } //00 00 
	condition:
		any of ($a_*)
 
}