
rule Trojan_Win32_CoinMiner_AE{
	meta:
		description = "Trojan:Win32/CoinMiner.AE,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {73 74 72 61 74 75 6d 2b 74 63 70 3a 2f 2f 70 6f 6f 6c 2e 73 75 70 70 6f 72 74 78 6d 72 2e 63 6f 6d } //01 00 
		$a_01_1 = {5c 74 61 73 6b 6d 67 72 2e 65 78 65 2e 6c 6e 6b } //01 00 
		$a_01_2 = {73 76 63 68 6f 73 74 2e 65 78 65 } //00 00 
	condition:
		any of ($a_*)
 
}