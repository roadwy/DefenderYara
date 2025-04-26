
rule Ransom_MSIL_Heracles_YAA_MTB{
	meta:
		description = "Ransom:MSIL/Heracles.YAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {02 6f 15 00 00 0a 0b 38 2c 00 00 00 07 17 59 0b 06 07 17 58 6f 16 00 00 0a 0c 02 08 6f 17 00 00 0a 0d 02 08 02 07 6f 17 00 00 0a 6f 18 00 00 0a 02 } //1
		$a_01_1 = {43 6f 6c 64 43 72 79 70 74 6f 72 } //1 ColdCryptor
		$a_01_2 = {52 61 6e 64 6f 6d 4e 75 6d 62 65 72 47 65 6e 65 72 61 74 6f 72 } //1 RandomNumberGenerator
		$a_01_3 = {45 6e 63 72 79 70 74 46 69 6c 65 } //1 EncryptFile
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}