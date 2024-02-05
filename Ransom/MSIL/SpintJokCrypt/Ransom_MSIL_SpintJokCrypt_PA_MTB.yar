
rule Ransom_MSIL_SpintJokCrypt_PA_MTB{
	meta:
		description = "Ransom:MSIL/SpintJokCrypt.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {2e 00 53 00 70 00 6c 00 69 00 6e 00 74 00 65 00 72 00 4a 00 6f 00 6b 00 65 00 } //01 00 
		$a_01_1 = {72 00 61 00 6e 00 73 00 6f 00 6d 00 5f 00 6e 00 6f 00 74 00 65 00 2e 00 74 00 78 00 74 00 } //01 00 
		$a_01_2 = {44 65 6c 65 74 65 53 68 61 64 6f 77 43 6f 70 69 65 73 } //01 00 
		$a_01_3 = {59 00 4f 00 55 00 52 00 20 00 46 00 49 00 4c 00 45 00 53 00 20 00 41 00 52 00 45 00 20 00 45 00 4e 00 43 00 52 00 59 00 50 00 54 00 45 00 44 00 } //00 00 
	condition:
		any of ($a_*)
 
}