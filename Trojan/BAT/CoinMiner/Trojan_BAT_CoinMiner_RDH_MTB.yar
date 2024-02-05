
rule Trojan_BAT_CoinMiner_RDH_MTB{
	meta:
		description = "Trojan:BAT/CoinMiner.RDH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 70 61 72 6b 20 41 63 74 69 76 61 74 6f 72 } //01 00 
		$a_01_1 = {51 6f 38 47 30 67 54 34 65 32 6b 4d 74 77 55 64 32 33 } //01 00 
		$a_01_2 = {72 46 52 53 65 33 41 61 73 6a 6e 6f 50 53 4a 37 6a 33 } //01 00 
		$a_01_3 = {64 6d 61 71 63 77 64 6e 73 74 6e 6d 65 70 67 6c } //00 00 
	condition:
		any of ($a_*)
 
}