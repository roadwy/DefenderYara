
rule Trojan_Win32_CoinMiner_PE{
	meta:
		description = "Trojan:Win32/CoinMiner.PE,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_03_0 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 90 02 20 2e 00 72 00 75 00 2f 00 90 02 10 2e 00 70 00 68 00 70 00 90 00 } //01 00 
		$a_01_1 = {73 63 68 74 61 73 6b 73 20 2f 63 72 65 61 74 65 20 2f 74 6e 20 5c 57 69 6e 64 6f 77 73 5c 53 65 72 76 69 63 65 52 75 6e 20 2f 74 72 } //01 00  schtasks /create /tn \Windows\ServiceRun /tr
		$a_01_2 = {63 72 79 70 74 6f 6e 69 67 68 74 } //01 00  cryptonight
		$a_01_3 = {73 74 72 61 74 75 6d 2b 74 63 70 3a 2f 2f } //01 00  stratum+tcp://
		$a_03_4 = {61 74 74 72 69 62 20 2b 73 20 2b 68 20 22 43 3a 5c 90 02 40 2e 65 78 65 22 90 00 } //00 00 
		$a_00_5 = {5d 04 00 } //00 a0 
	condition:
		any of ($a_*)
 
}