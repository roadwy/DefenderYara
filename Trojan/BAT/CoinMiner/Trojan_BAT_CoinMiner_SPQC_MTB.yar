
rule Trojan_BAT_CoinMiner_SPQC_MTB{
	meta:
		description = "Trojan:BAT/CoinMiner.SPQC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 02 00 "
		
	strings :
		$a_03_0 = {11 06 72 00 01 00 70 6f 90 01 03 0a 6f 90 01 03 0a 17 8d 16 00 00 01 13 0f 11 0f 16 1f 20 9d 11 0f 6f 90 01 03 0a 13 10 16 13 11 2b 28 11 10 11 11 9a 13 07 11 07 28 90 01 03 06 13 08 11 08 28 90 01 03 0a 2d 09 90 00 } //01 00 
		$a_01_1 = {6f 00 63 00 70 00 66 00 68 00 76 00 61 00 62 00 66 00 68 00 70 00 6c 00 79 00 78 00 6a 00 67 00 } //00 00 
	condition:
		any of ($a_*)
 
}