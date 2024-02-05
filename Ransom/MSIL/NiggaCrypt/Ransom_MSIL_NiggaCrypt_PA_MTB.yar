
rule Ransom_MSIL_NiggaCrypt_PA_MTB{
	meta:
		description = "Ransom:MSIL/NiggaCrypt.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {52 5f 41 5f 4e 5f 53 5f 4f 5f 4d 5f 57 5f 41 5f 52 5f 45 5f 5f 5f 46 5f 4f 5f 52 5f 5f 5f 59 5f 4f 5f 55 5f 5f 5f 4e 5f 49 5f 47 5f 47 5f 41 } //01 00 
		$a_01_1 = {5c 00 52 00 45 00 41 00 44 00 5f 00 4d 00 45 00 5f 00 46 00 41 00 47 00 47 00 4f 00 54 00 2e 00 74 00 78 00 74 00 } //01 00 
		$a_01_2 = {5c 48 65 72 61 78 77 61 72 65 2e 70 64 62 } //00 00 
		$a_00_3 = {5d 04 } //00 00 
	condition:
		any of ($a_*)
 
}