
rule Ransom_Linux_Criptato_A_MTB{
	meta:
		description = "Ransom:Linux/Criptato.A!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,0d 00 0d 00 06 00 00 "
		
	strings :
		$a_01_0 = {2e 66 75 63 6b } //5 .fuck
		$a_01_1 = {2e 63 72 79 70 74 } //5 .crypt
		$a_00_2 = {00 2e 2e 00 56 49 53 49 54 4f 20 25 73 20 43 48 45 20 43 4f 4e 54 49 45 4e 45 20 25 73 0a 00 72 62 00 77 62 00 } //5
		$a_01_3 = {63 72 69 70 74 61 74 6f } //1 criptato
		$a_01_4 = {56 69 73 69 74 44 65 63 72 79 70 74 } //1 VisitDecrypt
		$a_01_5 = {56 69 73 69 74 43 72 79 70 74 } //1 VisitCrypt
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5+(#a_00_2  & 1)*5+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=13
 
}