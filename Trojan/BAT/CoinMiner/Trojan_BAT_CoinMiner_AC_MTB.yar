
rule Trojan_BAT_CoinMiner_AC_MTB{
	meta:
		description = "Trojan:BAT/CoinMiner.AC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {7e 88 03 00 04 13 00 7e 89 03 00 04 7e 8a 03 00 04 7e 8b 03 00 04 61 7e 8c 03 00 04 40 0d 00 00 00 7e 42 00 00 04 13 00 7e 8d 03 00 04 58 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_CoinMiner_AC_MTB_2{
	meta:
		description = "Trojan:BAT/CoinMiner.AC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {11 22 11 23 9a 13 24 00 11 24 6f 90 01 03 0a 11 21 6f 90 01 03 0a fe 01 16 fe 01 13 25 11 25 2c 05 00 16 13 08 00 00 11 23 17 58 13 23 11 23 11 22 8e 69 32 cb 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}