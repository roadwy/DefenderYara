
rule Trojan_BAT_CoinMiner_ACM_MTB{
	meta:
		description = "Trojan:BAT/CoinMiner.ACM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 02 00 "
		
	strings :
		$a_03_0 = {0a 02 7b 5b 01 00 04 6a 58 06 20 90 01 03 00 64 0a e0 06 20 90 01 03 2f 5c 0a 47 02 02 7b 5b 01 00 04 06 90 00 } //01 00 
		$a_01_1 = {52 00 65 00 61 00 6c 00 55 00 49 00 2d 00 49 00 6e 00 73 00 74 00 61 00 6c 00 6c 00 65 00 72 00 2e 00 65 00 78 00 65 00 } //00 00  RealUI-Installer.exe
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_CoinMiner_ACM_MTB_2{
	meta:
		description = "Trojan:BAT/CoinMiner.ACM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {2b 2b 2b 30 1b 2c f9 1e 2c f6 2b 2b 2b 30 2b 31 2b 36 75 01 00 00 1b 2b 36 19 2c 0f 16 2d e1 2b 31 16 2b 31 8e 69 28 90 01 03 0a 07 2a 28 90 01 03 06 2b ce 0a 2b cd 28 90 01 03 0a 2b ce 06 2b cd 6f 90 01 03 0a 2b c8 28 90 01 03 06 2b c3 0b 2b c7 07 2b cc 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}