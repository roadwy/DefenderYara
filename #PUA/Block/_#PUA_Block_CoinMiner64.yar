
rule _#PUA_Block_CoinMiner64{
	meta:
		description = "!#PUA:Block:CoinMiner64,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 09 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 00 4f 00 46 00 54 00 57 00 41 00 52 00 45 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 5c 00 52 00 75 00 6e 00 } //01 00  SOFTWARE\Microsoft\Windows\CurrentVersion\Run
		$a_01_1 = {2d 00 2d 00 63 00 70 00 75 00 2d 00 6d 00 61 00 78 00 2d 00 74 00 68 00 72 00 65 00 61 00 64 00 73 00 2d 00 68 00 69 00 6e 00 74 00 20 00 35 00 30 00 20 00 2d 00 72 00 } //01 00  --cpu-max-threads-hint 50 -r
		$a_01_2 = {2d 00 6f 00 20 00 70 00 6f 00 6f 00 6c 00 2e 00 6d 00 69 00 6e 00 65 00 78 00 6d 00 72 00 2e 00 63 00 6f 00 6d 00 3a 00 34 00 34 00 34 00 34 00 20 00 2d 00 75 00 20 00 } //01 00  -o pool.minexmr.com:4444 -u 
		$a_01_3 = {65 00 74 00 68 00 65 00 72 00 65 00 75 00 6d 00 2d 00 6d 00 69 00 6e 00 69 00 6e 00 67 00 } //01 00  ethereum-mining
		$a_01_4 = {65 00 74 00 68 00 6d 00 69 00 6e 00 65 00 72 00 2e 00 65 00 78 00 65 00 } //01 00  ethminer.exe
		$a_01_5 = {77 00 61 00 75 00 70 00 64 00 61 00 74 00 33 00 2e 00 65 00 78 00 65 00 } //01 00  waupdat3.exe
		$a_01_6 = {6d 00 73 00 69 00 65 00 78 00 65 00 63 00 2e 00 65 00 78 00 65 00 } //01 00  msiexec.exe
		$a_01_7 = {2d 00 50 00 20 00 73 00 74 00 72 00 61 00 74 00 75 00 6d 00 31 00 } //01 00  -P stratum1
		$a_01_8 = {2f 00 78 00 6d 00 72 00 69 00 } //00 00  /xmri
	condition:
		any of ($a_*)
 
}
rule _#PUA_Block_CoinMiner64_2{
	meta:
		description = "!#PUA:Block:CoinMiner64,SIGNATURE_TYPE_PEHSTR,04 00 04 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {64 6f 6e 61 74 65 2e 76 32 2e 78 6d 72 69 67 2e 63 6f 6d } //01 00  donate.v2.xmrig.com
		$a_01_1 = {63 72 79 70 74 6f 6e 69 67 68 74 2d 6d 6f 6e 65 72 6f 76 37 } //01 00  cryptonight-monerov7
		$a_01_2 = {73 74 72 61 74 75 6d 2b 74 63 70 3a 2f 2f } //01 00  stratum+tcp://
		$a_01_3 = {6e 69 63 65 68 61 73 68 } //01 00  nicehash
		$a_01_4 = {64 6f 6e 61 74 65 2d 6f 76 65 72 2d 70 72 6f 78 79 } //01 00  donate-over-proxy
		$a_01_5 = {7b 22 69 64 22 3a 25 6c 6c 64 2c 22 6a 73 6f 6e 72 70 63 22 3a 22 32 2e 30 22 2c 22 6d 65 74 68 6f 64 22 3a 22 6b 65 65 70 61 6c 69 76 65 64 22 2c 22 70 61 72 61 6d 73 22 3a 7b 22 69 64 22 3a 22 25 73 22 7d 7d } //00 00  {"id":%lld,"jsonrpc":"2.0","method":"keepalived","params":{"id":"%s"}}
	condition:
		any of ($a_*)
 
}