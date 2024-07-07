
rule Ransom_MSIL_CryptJoker_PA_MTB{
	meta:
		description = "Ransom:MSIL/CryptJoker.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {43 00 72 00 79 00 70 00 74 00 6f 00 4a 00 6f 00 6b 00 65 00 72 00 2e 00 50 00 72 00 6f 00 70 00 65 00 72 00 74 00 69 00 65 00 73 00 } //1 CryptoJoker.Properties
		$a_01_1 = {4a 6f 6b 65 72 49 73 4e 6f 74 52 75 6e 6e 69 6e 67 } //1 JokerIsNotRunning
		$a_01_2 = {43 00 72 00 79 00 70 00 74 00 4a 00 6f 00 6b 00 65 00 72 00 57 00 61 00 6c 00 6b 00 65 00 72 00 39 00 30 00 39 00 31 00 32 00 } //1 CryptJokerWalker90912
		$a_01_3 = {5c 43 72 79 70 74 6f 4a 6f 6b 65 72 2e 70 64 62 } //1 \CryptoJoker.pdb
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}