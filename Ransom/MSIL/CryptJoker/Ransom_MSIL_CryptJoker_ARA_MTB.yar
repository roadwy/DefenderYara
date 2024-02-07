
rule Ransom_MSIL_CryptJoker_ARA_MTB{
	meta:
		description = "Ransom:MSIL/CryptJoker.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 02 00 "
		
	strings :
		$a_01_0 = {00 06 08 03 08 91 04 07 91 59 d2 9c 04 07 17 58 91 16 fe 01 0d 09 2c 04 16 0b 2b 04 07 17 58 0b 00 08 17 58 0c 08 03 8e 69 fe 04 13 04 11 04 2d cf } //06 00 
		$a_81_1 = {43 72 79 70 74 6f 4a 6f 6b 65 72 4d 65 73 73 61 67 65 } //03 00  CryptoJokerMessage
		$a_81_2 = {52 61 6e 73 6f 6d 77 61 72 65 } //03 00  Ransomware
		$a_81_3 = {42 69 74 63 6f 69 6e 41 64 72 65 73 73 } //00 00  BitcoinAdress
	condition:
		any of ($a_*)
 
}