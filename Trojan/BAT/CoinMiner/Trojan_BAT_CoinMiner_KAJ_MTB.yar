
rule Trojan_BAT_CoinMiner_KAJ_MTB{
	meta:
		description = "Trojan:BAT/CoinMiner.KAJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {11 08 1f 10 28 90 01 01 00 00 0a 8d 90 01 01 00 00 01 13 09 02 11 08 1f 14 28 90 01 01 00 00 0a 11 09 16 11 09 8e 69 28 90 01 01 00 00 0a 11 04 07 11 08 1f 0c 28 90 01 01 00 00 0a 6a 58 11 09 11 09 8e 69 16 6a 28 90 01 01 00 00 06 26 11 07 17 58 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}