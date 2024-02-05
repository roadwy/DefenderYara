
rule Trojan_BAT_CoinMiner_NHI_MTB{
	meta:
		description = "Trojan:BAT/CoinMiner.NHI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 05 00 "
		
	strings :
		$a_03_0 = {28 17 00 00 0a 0b 72 90 01 02 00 70 0c 73 90 01 02 00 0a 0d 09 07 72 90 01 02 00 70 08 28 90 01 02 00 0a 6f 90 01 02 00 0a 00 09 28 1b 00 00 0a 90 00 } //01 00 
		$a_01_1 = {47 4d 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 } //00 00 
	condition:
		any of ($a_*)
 
}