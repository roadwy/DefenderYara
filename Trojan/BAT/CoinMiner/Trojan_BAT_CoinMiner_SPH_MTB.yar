
rule Trojan_BAT_CoinMiner_SPH_MTB{
	meta:
		description = "Trojan:BAT/CoinMiner.SPH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {7e 17 00 00 04 28 90 01 03 0a 72 09 03 00 70 28 90 01 03 0a 80 0c 00 00 04 7e 0c 00 00 04 6f 90 01 03 0a 16 9a 7e 0d 00 00 04 73 52 00 00 0a 80 0e 00 00 04 18 17 1c 73 53 00 00 0a 80 0b 00 00 04 7e 0b 00 00 04 7e 0e 00 00 04 14 fe 06 14 00 00 06 73 54 00 00 0a 14 6f 90 01 03 0a 26 de 08 90 00 } //01 00 
		$a_01_1 = {72 00 6f 00 6f 00 74 00 62 00 6f 00 73 00 73 00 6b 00 6f 00 2e 00 64 00 75 00 63 00 6b 00 64 00 6e 00 73 00 2e 00 6f 00 72 00 67 00 } //00 00  rootbossko.duckdns.org
	condition:
		any of ($a_*)
 
}