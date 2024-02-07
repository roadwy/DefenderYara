
rule Trojan_BAT_CoinMiner_NRF_MTB{
	meta:
		description = "Trojan:BAT/CoinMiner.NRF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 03 00 00 05 00 "
		
	strings :
		$a_03_0 = {08 03 2d 18 07 06 28 90 01 03 0a 72 90 01 03 70 6f 90 01 03 0a 6f 90 01 03 0a 2b 16 07 06 28 90 01 03 0a 72 90 01 03 70 6f 90 01 03 0a 6f 90 01 03 0a 17 73 90 01 03 0a 0d 09 02 16 02 8e 69 6f 90 01 03 0a 90 00 } //05 00 
		$a_03_1 = {03 6f 2a 00 00 0a 2c 32 07 6f 90 01 03 0a 0c 73 90 01 03 0a 0d 08 09 6f 90 01 03 0a 09 6f 90 01 03 0a 90 00 } //01 00 
		$a_01_2 = {57 69 6e 64 6f 77 73 42 75 69 6c 74 49 6e 52 6f 6c 65 } //00 00  WindowsBuiltInRole
	condition:
		any of ($a_*)
 
}