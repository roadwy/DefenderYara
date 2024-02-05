
rule Trojan_Win32_CoinMiner_DY_bit{
	meta:
		description = "Trojan:Win32/CoinMiner.DY!bit,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 02 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 3a 2f 2f 67 65 79 2e 6d 6f 79 2e 73 75 2f 61 6d 6d 79 79 2e 7a 69 70 } //02 00 
		$a_01_1 = {68 74 74 70 3a 2f 2f 67 65 79 2e 6d 6f 79 2e 73 75 2f 74 65 6d 70 2e 7a 69 70 } //01 00 
		$a_01_2 = {5c 73 79 73 74 65 6d 5c 73 76 63 68 6f 73 74 2e 65 78 65 } //01 00 
		$a_01_3 = {75 70 64 61 74 61 2e 72 65 62 6f 6f 74 40 67 6d 61 69 6c 2e 63 6f 6d } //00 00 
	condition:
		any of ($a_*)
 
}