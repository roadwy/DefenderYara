
rule Trojan_Win64_CoinMiner_BSA_MTB{
	meta:
		description = "Trojan:Win64/CoinMiner.BSA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1b 00 1b 00 08 00 00 "
		
	strings :
		$a_01_0 = {55 73 61 67 65 3a 20 78 6d 72 69 67 20 5b 4f 50 54 49 4f 4e 53 5d } //10 Usage: xmrig [OPTIONS]
		$a_01_1 = {65 6e 61 62 6c 65 20 6e 69 63 65 68 61 73 68 2f 78 6d 72 69 67 2d 70 72 6f 78 79 } //6 enable nicehash/xmrig-proxy
		$a_01_2 = {63 72 79 70 74 6f 6e 69 67 68 74 } //1 cryptonight
		$a_01_3 = {63 72 79 70 74 6f 6e 69 67 68 74 2d 6c 69 74 65 } //2 cryptonight-lite
		$a_01_4 = {63 72 79 70 74 6f 6e 69 67 68 74 2d 6c 69 67 68 74 } //2 cryptonight-light
		$a_01_5 = {6d 61 78 69 6d 75 6d 20 43 50 55 20 75 73 61 67 65 20 66 6f 72 20 61 75 74 6f 6d 61 74 69 63 20 74 68 72 65 61 64 73 6d 6f 64 65 } //3 maximum CPU usage for automatic threadsmode
		$a_01_6 = {70 72 69 6e 74 20 68 61 73 68 72 61 74 65 20 72 65 70 6f 72 74 20 65 76 65 72 79 20 4e 20 73 65 63 6f 6e 64 73 } //4 print hashrate report every N seconds
		$a_01_7 = {70 6f 72 74 20 66 6f 72 20 74 68 65 20 6d 69 6e 65 72 20 41 50 49 } //5 port for the miner API
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*6+(#a_01_2  & 1)*1+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2+(#a_01_5  & 1)*3+(#a_01_6  & 1)*4+(#a_01_7  & 1)*5) >=27
 
}