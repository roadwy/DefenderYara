
rule Trojan_BAT_BitcoinMiner_A{
	meta:
		description = "Trojan:BAT/BitcoinMiner.A,SIGNATURE_TYPE_PEHSTR,04 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {49 00 6e 00 6a 00 65 00 63 00 74 00 50 00 45 00 } //01 00  InjectPE
		$a_01_1 = {69 00 6e 00 66 00 69 00 6e 00 69 00 74 00 79 00 62 00 6f 00 74 00 } //01 00  infinitybot
		$a_01_2 = {63 00 67 00 6d 00 69 00 6e 00 65 00 72 00 } //01 00  cgminer
		$a_01_3 = {63 00 6f 00 69 00 6e 00 2d 00 6d 00 69 00 6e 00 65 00 72 00 } //01 00  coin-miner
		$a_01_4 = {42 00 69 00 74 00 63 00 6f 00 69 00 6e 00 4d 00 69 00 6e 00 65 00 72 00 } //00 00  BitcoinMiner
		$a_01_5 = {00 67 16 } //00 00 
	condition:
		any of ($a_*)
 
}