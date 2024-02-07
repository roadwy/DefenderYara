
rule Trojan_Win32_CoinMiner_BK_bit{
	meta:
		description = "Trojan:Win32/CoinMiner.BK!bit,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 03 00 00 0a 00 "
		
	strings :
		$a_01_0 = {63 70 75 5f 74 72 6f 6d 70 5f 53 53 45 } //0a 00  cpu_tromp_SSE
		$a_01_1 = {5c 00 53 00 79 00 73 00 74 00 65 00 6d 00 5c 00 6e 00 68 00 65 00 71 00 6d 00 69 00 6e 00 65 00 72 00 } //01 00  \System\nheqminer
		$a_03_2 = {64 00 2e 00 74 00 6f 00 70 00 34 00 74 00 6f 00 70 00 2e 00 6e 00 65 00 74 00 2f 00 90 02 1f 2e 00 6a 00 70 00 67 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}