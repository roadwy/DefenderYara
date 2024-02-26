
rule Trojan_BAT_CoinMiner_PTDH_MTB{
	meta:
		description = "Trojan:BAT/CoinMiner.PTDH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {7e c0 5d 00 04 28 90 01 01 01 00 06 28 90 01 01 00 00 06 28 90 01 01 01 00 06 28 90 01 01 00 00 0a 28 90 01 01 00 00 0a 28 90 01 01 00 00 0a 13 09 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}