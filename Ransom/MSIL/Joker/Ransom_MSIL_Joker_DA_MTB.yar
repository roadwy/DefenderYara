
rule Ransom_MSIL_Joker_DA_MTB{
	meta:
		description = "Ransom:MSIL/Joker.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_81_0 = {43 72 79 70 74 6f 4a 6f 6b 65 72 2e 65 78 65 } //01 00  CryptoJoker.exe
		$a_81_1 = {43 72 79 70 74 6f 4a 6f 6b 65 72 2e 50 72 6f 70 65 72 74 69 65 73 } //01 00  CryptoJoker.Properties
		$a_81_2 = {6a 6f 6b 69 6e 67 77 69 74 68 79 6f 75 2e 63 72 79 70 74 6f 6a 6f 6b 65 72 } //01 00  jokingwithyou.cryptojoker
		$a_81_3 = {2e 63 72 79 70 74 6f 6a 6f 6b 65 72 } //01 00  .cryptojoker
		$a_81_4 = {4a 6f 6b 65 72 49 73 4e 6f 74 52 75 6e 6e 69 6e 67 } //00 00  JokerIsNotRunning
	condition:
		any of ($a_*)
 
}