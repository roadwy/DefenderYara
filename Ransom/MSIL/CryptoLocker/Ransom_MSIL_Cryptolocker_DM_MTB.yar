
rule Ransom_MSIL_Cryptolocker_DM_MTB{
	meta:
		description = "Ransom:MSIL/Cryptolocker.DM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,42 00 42 00 0c 00 00 "
		
	strings :
		$a_81_0 = {55 48 4a 76 61 6d 56 6a 64 45 5a 79 61 57 52 68 65 53 55 } //50 UHJvamVjdEZyaWRheSU
		$a_81_1 = {46 61 74 75 72 61 57 61 6c 6b 65 72 } //50 FaturaWalker
		$a_81_2 = {46 61 74 75 72 61 20 42 69 6c 67 69 6c 65 6e 64 69 72 6d 65 } //50 Fatura Bilgilendirme
		$a_81_3 = {46 72 69 64 61 79 50 72 6f 6a 65 63 74 2e 50 72 6f 70 65 72 74 69 65 73 } //10 FridayProject.Properties
		$a_81_4 = {46 61 74 75 72 61 44 65 63 72 79 70 74 6f 72 } //10 FaturaDecryptor
		$a_81_5 = {46 61 74 75 72 61 2d 6d 61 73 74 65 72 } //10 Fatura-master
		$a_81_6 = {43 72 79 70 74 6f 4f 62 66 75 73 63 61 74 6f 72 } //5 CryptoObfuscator
		$a_01_7 = {45 6e 63 72 79 70 74 69 6f 6e 4b 65 79 } //5 EncryptionKey
		$a_81_8 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_81_9 = {65 6e 63 4b 65 79 2e 61 65 73 } //1 encKey.aes
		$a_81_10 = {52 6d 46 30 64 58 4a 68 56 32 46 73 61 32 56 79 4f 54 41 35 4d 54 49 } //1 RmF0dXJhV2Fsa2VyOTA5MTI
		$a_81_11 = {45 6e 63 72 79 70 74 46 69 6c 65 46 75 6c 6c 79 } //1 EncryptFileFully
	condition:
		((#a_81_0  & 1)*50+(#a_81_1  & 1)*50+(#a_81_2  & 1)*50+(#a_81_3  & 1)*10+(#a_81_4  & 1)*10+(#a_81_5  & 1)*10+(#a_81_6  & 1)*5+(#a_01_7  & 1)*5+(#a_81_8  & 1)*1+(#a_81_9  & 1)*1+(#a_81_10  & 1)*1+(#a_81_11  & 1)*1) >=66
 
}