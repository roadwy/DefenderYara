
rule Ransom_MSIL_Joker_DB_MTB{
	meta:
		description = "Ransom:MSIL/Joker.DB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_81_0 = {43 72 79 70 74 6f 4a 6f 6b 65 72 4d 65 73 73 61 67 65 } //1 CryptoJokerMessage
		$a_81_1 = {67 65 74 5f 43 72 79 70 74 6f 4a 6f 6b 65 72 } //1 get_CryptoJoker
		$a_81_2 = {45 6e 63 72 79 70 74 69 6f 6e 4b 65 79 } //1 EncryptionKey
		$a_81_3 = {4e 6f 43 72 79 43 72 79 70 74 6f 72 } //1 NoCryCryptor
		$a_81_4 = {43 72 79 70 74 6f 4a 6f 6b 65 72 2e 50 72 6f 70 65 72 74 69 65 73 } //1 CryptoJoker.Properties
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}