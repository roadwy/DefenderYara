
rule Trojan_BAT_CoinMiner_CQ_bit{
	meta:
		description = "Trojan:BAT/CoinMiner.CQ!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 75 70 72 65 6d 65 2e 65 78 65 00 53 75 70 72 65 6d 65 00 6d 73 63 6f 72 6c 69 62 00 } //01 00 
		$a_01_1 = {44 65 62 75 67 67 65 72 00 67 65 74 5f 49 73 41 74 74 61 63 68 65 64 00 49 73 4c 6f 67 67 69 6e 67 } //00 00 
	condition:
		any of ($a_*)
 
}