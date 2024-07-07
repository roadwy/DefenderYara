
rule Ransom_Linux_Conti_D_MTB{
	meta:
		description = "Ransom:Linux/Conti.D!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {2e 63 6f 6e 74 69 } //1 .conti
		$a_01_1 = {2e 2f 6c 6f 63 6b 65 72 20 2d 2d 70 61 74 68 20 2f 70 61 74 68 } //1 ./locker --path /path
		$a_01_2 = {49 6e 69 74 69 61 6c 69 7a 65 45 6e 63 72 79 70 74 6f 72 } //1 InitializeEncryptor
		$a_01_3 = {43 4f 4e 54 49 5f 52 45 41 44 4d 45 2e 74 78 74 } //1 CONTI_README.txt
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}