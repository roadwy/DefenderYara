
rule Trojan_BAT_CoinMiner_MBDS_MTB{
	meta:
		description = "Trojan:BAT/CoinMiner.MBDS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {0b 07 72 21 05 00 70 72 25 05 00 70 6f 90 01 01 00 00 0a 72 2b 05 00 70 72 31 05 00 70 6f 90 01 01 00 00 0a 0b 73 00 01 00 0a 0c 16 0d 2b 23 00 07 09 18 6f 90 01 01 01 00 0a 20 03 02 00 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}