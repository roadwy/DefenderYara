
rule Ransom_MSIL_RUsom_DA_MTB{
	meta:
		description = "Ransom:MSIL/RUsom.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {52 00 55 00 5f 00 52 00 61 00 6e 00 73 00 6f 00 6d 00 } //1 RU_Ransom
		$a_01_1 = {65 6e 63 72 79 70 74 41 6c 6c 44 69 72 65 63 74 6f 72 79 } //1 encryptAllDirectory
		$a_01_2 = {67 65 74 45 6e 63 72 79 70 74 65 64 41 65 73 4b 65 79 } //1 getEncryptedAesKey
		$a_01_3 = {41 45 53 5f 45 6e 63 72 79 70 74 } //1 AES_Encrypt
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}