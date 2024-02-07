
rule Trojan_BAT_CoinMiner_EAC_MTB{
	meta:
		description = "Trojan:BAT/CoinMiner.EAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 04 00 "
		
	strings :
		$a_03_0 = {0a 0b 16 0c 07 8e 69 17 59 0d 38 90 01 01 00 00 00 07 08 91 13 04 07 08 07 09 91 9c 07 09 11 04 9c 08 17 58 0c 09 17 59 0d 08 09 32 e4 07 13 05 dd 90 01 01 00 00 00 26 de b4 90 00 } //01 00 
		$a_01_1 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //00 00  FromBase64String
	condition:
		any of ($a_*)
 
}