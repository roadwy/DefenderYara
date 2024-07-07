
rule Ransom_Win64_SeivCrypt_PA_MTB{
	meta:
		description = "Ransom:Win64/SeivCrypt.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {2e 73 65 69 76 } //1 .seiv
		$a_03_1 = {5c 70 72 69 76 61 74 65 90 02 10 2e 65 6e 63 72 79 70 74 65 64 90 00 } //1
		$a_03_2 = {5c 41 72 74 4f 66 43 72 79 70 74 5c 90 02 15 5c 45 4e 63 72 79 70 74 30 72 2e 70 64 62 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}