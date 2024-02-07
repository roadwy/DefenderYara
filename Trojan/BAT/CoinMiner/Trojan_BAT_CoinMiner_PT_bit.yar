
rule Trojan_BAT_CoinMiner_PT_bit{
	meta:
		description = "Trojan:BAT/CoinMiner.PT!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {73 00 74 00 72 00 61 00 74 00 75 00 6d 00 2b 00 74 00 63 00 70 00 3a 00 2f 00 2f 00 78 00 6d 00 72 00 2e 00 } //01 00  stratum+tcp://xmr.
		$a_03_1 = {54 00 61 00 73 00 6b 00 4d 00 67 00 72 00 90 02 02 46 00 69 00 6c 00 74 00 65 00 72 00 48 00 6f 00 73 00 74 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}