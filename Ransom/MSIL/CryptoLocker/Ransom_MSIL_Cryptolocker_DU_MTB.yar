
rule Ransom_MSIL_Cryptolocker_DU_MTB{
	meta:
		description = "Ransom:MSIL/Cryptolocker.DU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,4a 00 4a 00 08 00 00 32 00 "
		
	strings :
		$a_81_0 = {43 72 79 70 74 6f 5f 54 68 65 4f 6e 6c 79 4f 6e 65 } //32 00  Crypto_TheOnlyOne
		$a_81_1 = {68 69 64 64 65 6e 2d 74 65 61 72 } //14 00  hidden-tear
		$a_81_2 = {53 50 4c 49 54 54 54 54 } //14 00  SPLITTTT
		$a_81_3 = {68 69 64 64 65 6e 5f 74 65 61 72 2e 50 72 6f 70 65 72 74 69 65 73 } //03 00  hidden_tear.Properties
		$a_81_4 = {4c 4f 43 4b 54 48 41 54 } //03 00  LOCKTHAT
		$a_81_5 = {57 72 6f 6e 67 20 48 65 61 64 65 72 20 53 69 67 6e 61 74 75 72 65 } //01 00  Wrong Header Signature
		$a_81_6 = {42 54 43 20 41 64 64 72 65 73 73 20 3a } //01 00  BTC Address :
		$a_81_7 = {47 65 74 54 65 6d 70 50 61 74 68 } //00 00  GetTempPath
	condition:
		any of ($a_*)
 
}