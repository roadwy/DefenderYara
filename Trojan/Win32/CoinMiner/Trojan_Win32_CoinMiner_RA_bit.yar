
rule Trojan_Win32_CoinMiner_RA_bit{
	meta:
		description = "Trojan:Win32/CoinMiner.RA!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {45 74 65 72 6e 61 6c 42 6c 75 65 5c 45 6d 70 74 79 50 72 6f 6a 65 63 74 [0-20] 2e 70 64 62 } //1
		$a_01_1 = {49 6e 74 65 6c 20 53 74 6f 72 61 67 65 20 53 65 72 76 69 63 65 } //1 Intel Storage Service
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}