
rule Ransom_MSIL_Joker_DC_MTB{
	meta:
		description = "Ransom:MSIL/Joker.DC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_81_0 = {43 72 79 70 74 6f 4a 6f 6b 65 72 44 65 63 72 79 70 74 6f 72 } //01 00  CryptoJokerDecryptor
		$a_81_1 = {40 70 72 6f 74 6f 6e 6d 61 69 6c 2e 63 6f 6d } //01 00  @protonmail.com
		$a_81_2 = {44 61 72 6b 20 4d 61 74 74 65 72 20 52 65 63 6f 76 65 72 79 20 49 6e 66 6f 72 6d 61 74 69 6f 6e 2e 74 78 74 } //01 00  Dark Matter Recovery Information.txt
		$a_81_3 = {6a 6f 6b 69 6e 67 77 69 74 68 79 6f 75 } //01 00  jokingwithyou
		$a_81_4 = {42 69 74 63 6f 69 6e 20 41 64 64 72 65 73 73 } //00 00  Bitcoin Address
	condition:
		any of ($a_*)
 
}