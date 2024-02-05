
rule Trojan_BAT_CoinMiner_ME_MTB{
	meta:
		description = "Trojan:BAT/CoinMiner.ME!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 06 00 00 0a 00 "
		
	strings :
		$a_03_0 = {0a 16 0b 16 0c 2b 27 02 08 8f 90 01 03 01 25 71 90 01 03 01 06 07 25 17 58 0b 91 61 d2 81 90 01 03 01 07 06 8e 69 33 02 16 0b 08 17 58 0c 08 02 8e 69 32 d3 02 2a 90 00 } //01 00 
		$a_01_1 = {44 65 63 72 79 70 74 } //01 00 
		$a_01_2 = {47 65 74 42 79 74 65 73 } //01 00 
		$a_01_3 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //01 00 
		$a_01_4 = {52 61 6e 64 6f 6d 50 61 73 73 4e 65 77 } //01 00 
		$a_01_5 = {44 79 6e 61 6d 69 63 49 6e 76 6f 6b 65 } //00 00 
	condition:
		any of ($a_*)
 
}