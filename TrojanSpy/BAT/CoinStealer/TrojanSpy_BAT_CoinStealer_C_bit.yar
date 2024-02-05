
rule TrojanSpy_BAT_CoinStealer_C_bit{
	meta:
		description = "TrojanSpy:BAT/CoinStealer.C!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {42 69 74 63 6f 69 6e 53 74 65 61 6c 65 72 2e 65 78 65 } //01 00 
		$a_01_1 = {44 65 6c 65 74 65 49 74 73 65 6c 66 } //01 00 
		$a_00_2 = {53 00 4f 00 46 00 54 00 57 00 41 00 52 00 45 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 5c 00 52 00 75 00 6e 00 } //00 00 
	condition:
		any of ($a_*)
 
}