
rule Trojan_BAT_CoinMiner_NHC_MTB{
	meta:
		description = "Trojan:BAT/CoinMiner.NHC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 05 00 "
		
	strings :
		$a_03_0 = {fe 0c 46 00 20 0c 00 00 00 fe 90 01 02 00 9c 20 90 01 03 00 38 90 01 03 ff 11 72 11 61 11 14 58 11 28 11 3b 5f 11 71 1f 1f 5f 64 d2 9c 20 90 01 03 00 38 90 01 03 ff 90 00 } //01 00 
		$a_01_1 = {57 72 69 74 65 41 6c 6c 42 79 74 65 73 } //01 00 
		$a_01_2 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //00 00 
	condition:
		any of ($a_*)
 
}