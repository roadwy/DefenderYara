
rule Trojan_BAT_CoinMiner_MBAK_MTB{
	meta:
		description = "Trojan:BAT/CoinMiner.MBAK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {2e 00 72 00 00 05 65 00 73 00 00 05 6f 00 75 00 00 05 72 00 63 } //01 00 
		$a_01_1 = {6a 00 6d 00 79 00 6a 00 67 00 35 00 00 0b 6a 00 6d 00 6d 00 72 00 35 } //01 00 
		$a_01_2 = {73 00 6e 00 76 00 6f 00 6f 00 64 00 38 00 } //01 00 
		$a_01_3 = {53 00 67 00 66 00 66 00 67 00 35 00 } //00 00 
	condition:
		any of ($a_*)
 
}