
rule Trojan_Win64_CoinMiner_P_bit{
	meta:
		description = "Trojan:Win64/CoinMiner.P!bit,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {73 76 63 68 6f 73 74 2e 65 78 65 20 69 6e 73 74 61 6c 6c 20 57 69 6e 64 6f 77 73 } //01 00 
		$a_01_1 = {2d 61 20 63 72 79 70 74 6f 6e 69 67 68 74 2d 6c 69 74 65 20 2d 6f 20 73 74 72 61 74 75 6d 2b 74 63 70 3a 2f 2f 61 65 6f 6e 2e 70 6f 6f 6c 2e 6d 69 6e 65 72 67 61 74 65 2e 63 6f 6d } //00 00 
	condition:
		any of ($a_*)
 
}