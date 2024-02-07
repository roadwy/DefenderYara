
rule Trojan_Win64_CoinMiner_C{
	meta:
		description = "Trojan:Win64/CoinMiner.C,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {6c 65 65 62 6f 6e 64 39 38 36 40 67 6d 61 69 6c 2e 63 6f 6d 00 } //01 00 
		$a_01_1 = {6c 65 65 62 6f 6e 64 39 38 36 40 67 6d 61 69 6c 2e 63 6f 6d 3a 78 } //01 00  leebond986@gmail.com:x
		$a_01_2 = {31 35 30 2e 38 2e 31 32 31 2e 39 39 } //01 00  150.8.121.99
		$a_01_3 = {73 74 72 61 74 75 6d 2b 74 63 70 3a 2f 2f 78 6d 72 2e 70 6f 6f 6c 2e 6d 69 6e 65 72 67 61 74 65 2e 63 6f 6d 3a 34 35 35 36 30 } //00 00  stratum+tcp://xmr.pool.minergate.com:45560
	condition:
		any of ($a_*)
 
}