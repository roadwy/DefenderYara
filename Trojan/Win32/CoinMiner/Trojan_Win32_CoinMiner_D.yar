
rule Trojan_Win32_CoinMiner_D{
	meta:
		description = "Trojan:Win32/CoinMiner.D,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {62 69 74 63 6f 69 6e 2d 6d 69 6e 65 72 } //01 00  bitcoin-miner
		$a_01_1 = {6d 69 64 73 74 61 74 65 7c 64 61 74 61 7c 68 61 73 68 31 7c 74 61 72 67 65 74 } //01 00  midstate|data|hash1|target
		$a_00_2 = {53 65 72 76 65 72 20 32 30 30 38 20 52 32 } //01 00  Server 2008 R2
		$a_00_3 = {2d 6f 20 68 74 74 70 3a 2f 2f 72 72 2e 62 74 63 6d 70 2e 63 6f 6d 3a 38 33 33 32 20 2d 75 } //00 00  -o http://rr.btcmp.com:8332 -u
	condition:
		any of ($a_*)
 
}