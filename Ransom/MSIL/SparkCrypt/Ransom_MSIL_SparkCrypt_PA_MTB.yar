
rule Ransom_MSIL_SparkCrypt_PA_MTB{
	meta:
		description = "Ransom:MSIL/SparkCrypt.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {2e 00 53 00 70 00 61 00 72 00 6b 00 } //01 00 
		$a_01_1 = {52 00 41 00 4e 00 53 00 4f 00 4d 00 57 00 41 00 52 00 45 00 33 00 2e 00 5f 00 30 00 } //01 00 
		$a_01_2 = {73 00 68 00 75 00 74 00 64 00 6f 00 77 00 6e 00 20 00 2f 00 72 00 20 00 2f 00 74 00 20 00 30 00 } //01 00 
		$a_01_3 = {5c 52 41 4e 53 4f 4d 57 41 52 45 33 2e 30 2e 70 64 62 } //00 00 
	condition:
		any of ($a_*)
 
}