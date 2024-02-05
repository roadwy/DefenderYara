
rule Trojan_BAT_CoinMiner_AX_bit{
	meta:
		description = "Trojan:BAT/CoinMiner.AX!bit,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {78 53 69 6c 65 6e 74 4d 6f 64 65 } //01 00 
		$a_01_1 = {78 42 61 73 65 36 34 44 65 63 6f 64 65 } //01 00 
		$a_01_2 = {78 42 61 73 65 36 34 45 6e 63 6f 64 65 } //01 00 
		$a_01_3 = {78 53 65 6e 64 52 65 71 75 65 73 74 } //01 00 
		$a_01_4 = {78 50 72 6f 63 65 73 73 53 74 61 72 74 } //01 00 
		$a_01_5 = {78 53 65 74 41 75 74 6f 52 75 6e } //00 00 
	condition:
		any of ($a_*)
 
}