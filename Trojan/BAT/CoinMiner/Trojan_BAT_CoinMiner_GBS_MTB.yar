
rule Trojan_BAT_CoinMiner_GBS_MTB{
	meta:
		description = "Trojan:BAT/CoinMiner.GBS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 0a 00 "
		
	strings :
		$a_03_0 = {11 12 11 13 9a 13 04 11 04 28 90 01 03 06 13 05 07 72 90 01 03 70 11 05 28 90 01 03 0a 6f 90 01 03 0a 2d 17 09 72 90 01 03 70 28 90 01 03 06 11 05 28 90 01 03 0a 6f 90 01 03 0a 11 13 17 58 13 13 11 13 11 12 8e 69 90 00 } //01 00 
		$a_01_1 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //01 00 
		$a_01_2 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //00 00 
	condition:
		any of ($a_*)
 
}