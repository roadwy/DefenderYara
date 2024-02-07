
rule Trojan_BAT_CoinMiner_GDD_MTB{
	meta:
		description = "Trojan:BAT/CoinMiner.GDD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 0a 00 "
		
	strings :
		$a_03_0 = {11 04 16 11 04 8e b7 6f 90 01 03 0a 13 05 08 11 05 6f 90 01 03 0a 08 18 6f 90 01 03 0a 08 17 6f 90 01 02 00 0a 08 6f 90 01 03 0a 02 16 02 8e b7 6f 90 01 03 0a 0d 09 0a de 0c de 0a 90 00 } //01 00 
		$a_01_1 = {54 6f 42 61 73 65 36 34 53 74 72 69 6e 67 } //01 00  ToBase64String
		$a_01_2 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //00 00  CreateDecryptor
	condition:
		any of ($a_*)
 
}