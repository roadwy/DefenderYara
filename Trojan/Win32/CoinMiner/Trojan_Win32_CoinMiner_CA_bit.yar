
rule Trojan_Win32_CoinMiner_CA_bit{
	meta:
		description = "Trojan:Win32/CoinMiner.CA!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 8c 24 3c 04 00 00 89 34 24 81 f1 90 02 04 89 c8 89 8c 24 3c 04 00 00 f7 e2 c1 ea 08 69 d2 33 01 00 00 29 d1 8b 04 8d 80 26 48 00 90 00 } //01 00 
		$a_00_1 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 20 4e 54 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 57 69 6e 6c 6f 67 6f 6e } //01 00 
		$a_00_2 = {63 70 75 6d 69 6e 65 72 2d 6d 75 6c 74 69 } //00 00 
	condition:
		any of ($a_*)
 
}