
rule Trojan_BAT_CoinMiner_GCV_MTB{
	meta:
		description = "Trojan:BAT/CoinMiner.GCV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 04 00 00 0a 00 "
		
	strings :
		$a_03_0 = {11 14 11 15 9a 13 0e 11 0c 11 0e 16 9a 6f 90 01 03 0a 2d 70 11 0e 17 9a 72 90 01 04 28 90 01 03 06 28 90 01 03 0a 2d 19 11 0e 17 9a 72 90 01 04 28 90 01 03 06 28 90 01 03 0a 2c 46 11 0b 2c 42 11 0e 17 9a 72 90 01 04 28 90 01 03 06 28 90 01 03 0a 2d 04 11 0a 2b 02 90 00 } //01 00 
		$a_01_1 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //01 00  CreateDecryptor
		$a_01_2 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //01 00  FromBase64String
		$a_01_3 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //00 00  VirtualProtect
	condition:
		any of ($a_*)
 
}