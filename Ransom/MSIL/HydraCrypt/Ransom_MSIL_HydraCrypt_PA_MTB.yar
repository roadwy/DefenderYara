
rule Ransom_MSIL_HydraCrypt_PA_MTB{
	meta:
		description = "Ransom:MSIL/HydraCrypt.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {2e 00 48 00 59 00 44 00 52 00 41 00 } //01 00 
		$a_01_1 = {2f 00 48 00 59 00 44 00 52 00 41 00 3b 00 63 00 6f 00 6d 00 70 00 6f 00 6e 00 65 00 6e 00 74 00 2f 00 6d 00 61 00 69 00 6e 00 77 00 69 00 6e 00 64 00 6f 00 77 00 2e 00 78 00 61 00 6d 00 6c 00 } //01 00 
		$a_01_2 = {5c 48 59 44 52 41 2e 70 64 62 } //00 00 
	condition:
		any of ($a_*)
 
}