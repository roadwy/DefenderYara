
rule Trojan_BAT_CoinMiner_L_bit{
	meta:
		description = "Trojan:BAT/CoinMiner.L!bit,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {09 11 06 09 11 06 91 04 61 d2 9c 11 06 17 58 } //01 00 
		$a_01_1 = {02 03 61 0c 08 1f 11 5a 1f 1b 5b 0c 07 1d 08 58 } //01 00 
		$a_01_2 = {4d 69 63 72 6f 73 6f 66 74 5c 4e 65 74 77 6f 72 6b 5c 43 6f 6e 6e 65 63 74 69 6f 6e 73 5c 68 6f 73 74 64 6c 2e 65 78 65 } //01 00 
		$a_01_3 = {6d 69 6e 69 6e 67 44 65 76 69 63 65 00 63 70 75 6c 6f 61 64 } //01 00 
		$a_01_4 = {6d 69 6e 65 72 54 61 73 6b } //01 00 
		$a_01_5 = {6c 6f 61 64 69 6e 67 63 70 75 } //00 00 
	condition:
		any of ($a_*)
 
}