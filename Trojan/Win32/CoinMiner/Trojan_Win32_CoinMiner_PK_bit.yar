
rule Trojan_Win32_CoinMiner_PK_bit{
	meta:
		description = "Trojan:Win32/CoinMiner.PK!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {00 6c 61 69 79 61 77 61 6b 75 61 6e 67 61 00 } //01 00 
		$a_01_1 = {00 5c 77 6b 73 7a 2e 69 6e 69 00 } //01 00 
		$a_01_2 = {73 74 72 61 74 75 6d 2b 74 63 70 3a 2f 2f 67 65 74 2e 62 69 2d 63 68 69 2e 63 6f 6d 3a 33 33 33 33 20 2d 75 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_CoinMiner_PK_bit_2{
	meta:
		description = "Trojan:Win32/CoinMiner.PK!bit,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 06 00 00 0a 00 "
		
	strings :
		$a_03_0 = {8b 47 3c 05 f8 00 00 00 c7 85 90 01 02 ff ff 2e 70 6c 61 03 c1 66 c7 85 90 01 02 ff ff 74 6f 03 c7 90 00 } //0a 00 
		$a_03_1 = {80 c9 ff 02 c2 32 c2 d0 c0 2a c8 b0 90 01 01 80 f1 90 01 01 2a c1 88 44 15 90 01 01 42 83 fa 90 01 01 72 e0 90 09 04 00 8a 44 15 90 00 } //01 00 
		$a_01_2 = {64 a1 30 00 00 00 8b 40 0c 8b 40 14 8b 00 8b 00 8b 40 10 89 45 fc } //01 00 
		$a_01_3 = {00 00 73 00 76 00 63 00 68 00 6f 00 73 00 74 00 78 00 36 00 34 00 2e 00 65 00 78 00 65 00 00 00 } //01 00 
		$a_01_4 = {00 00 73 00 61 00 64 00 6b 00 6c 00 6a 00 6d 00 38 00 73 00 00 00 } //01 00 
		$a_01_5 = {2f 00 53 00 43 00 20 00 4d 00 49 00 4e 00 55 00 54 00 45 00 20 00 2f 00 4d 00 4f 00 20 00 31 00 20 00 2f 00 46 00 20 00 2f 00 43 00 72 00 65 00 61 00 74 00 65 00 20 00 2f 00 54 00 4e 00 } //00 00 
		$a_00_6 = {5d 04 00 } //00 8d 
	condition:
		any of ($a_*)
 
}