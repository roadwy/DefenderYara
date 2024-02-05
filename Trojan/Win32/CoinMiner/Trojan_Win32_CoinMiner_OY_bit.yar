
rule Trojan_Win32_CoinMiner_OY_bit{
	meta:
		description = "Trojan:Win32/CoinMiner.OY!bit,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 02 00 "
		
	strings :
		$a_81_0 = {63 70 75 6d 69 6e 65 72 2d 6d 75 6c 74 69 } //01 00 
		$a_01_1 = {5c 77 69 6e 5f 78 38 36 2e 76 62 73 } //01 00 
		$a_01_2 = {5c 52 55 4e 2d 58 31 31 2d 78 38 36 2e 62 61 74 } //02 00 
		$a_01_3 = {50 61 74 68 3d 43 3a 5c 57 69 6e 64 6f 77 73 5c 54 65 6d 70 0d 0a 53 61 76 65 50 61 74 68 } //02 00 
		$a_01_4 = {54 65 6d 70 4d 6f 64 65 0d 0a 53 69 6c 65 6e 74 3d 31 } //00 00 
	condition:
		any of ($a_*)
 
}