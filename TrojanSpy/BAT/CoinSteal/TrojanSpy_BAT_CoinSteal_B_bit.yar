
rule TrojanSpy_BAT_CoinSteal_B_bit{
	meta:
		description = "TrojanSpy:BAT/CoinSteal.B!bit,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {56 69 63 74 69 6d 4c 6f 67 73 } //01 00 
		$a_01_1 = {42 69 74 63 6f 69 6e 57 61 6c 6c 65 74 } //01 00 
		$a_01_2 = {53 65 6e 64 55 72 6c 41 6e 64 45 78 65 63 75 74 65 } //01 00 
		$a_01_3 = {67 65 74 5f 53 63 72 65 65 6e 73 68 6f 74 } //00 00 
	condition:
		any of ($a_*)
 
}