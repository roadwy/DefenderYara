
rule Trojan_Win32_CoinMiner_AF{
	meta:
		description = "Trojan:Win32/CoinMiner.AF,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {48 00 61 00 70 00 69 00 2d 00 6d 00 73 00 2d 00 77 00 69 00 6e 00 2d 00 63 00 6f 00 72 00 65 00 2d 00 73 00 79 00 6e 00 63 00 68 00 2d 00 6c 00 31 00 2d 00 32 00 2d 00 30 00 2e 00 64 00 6c 00 6c 00 } //01 00  Hapi-ms-win-core-synch-l1-2-0.dll
		$a_01_1 = {2f 67 69 74 68 75 62 2e 63 6f 6d 2f 42 65 6e 64 72 30 69 64 2f 43 6d 72 63 53 65 72 76 69 63 65 43 43 2f 77 69 6b 69 2f 43 6f 69 6e 2d 63 6f 6e 66 69 67 75 72 61 74 69 6f 6e 73 } //01 00  /github.com/Bendr0id/CmrcServiceCC/wiki/Coin-configurations
		$a_01_2 = {73 75 62 6d 69 74 22 2c 22 70 61 72 61 6d 73 22 3a 7b 22 69 64 22 3a 22 25 73 22 2c 22 6a 6f 62 5f 69 64 22 3a 22 25 73 22 2c 22 6e 6f 6e 63 65 22 3a 22 25 73 22 2c 22 72 65 73 75 6c 74 } //01 00  submit","params":{"id":"%s","job_id":"%s","nonce":"%s","result
		$a_01_3 = {54 00 72 00 65 00 6e 00 64 00 20 00 4d 00 69 00 63 00 72 00 6f 00 20 00 54 00 69 00 74 00 61 00 6e 00 69 00 75 00 6d 00 } //00 00  Trend Micro Titanium
	condition:
		any of ($a_*)
 
}