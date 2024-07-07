
rule Misleading_MacOS_CoinMiner_BA_MTB{
	meta:
		description = "Misleading:MacOS/CoinMiner.BA!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,03 00 03 00 06 00 00 "
		
	strings :
		$a_00_0 = {58 4d 52 2d 53 74 61 6b 2d 4d 69 6e 65 72 } //2 XMR-Stak-Miner
		$a_00_1 = {43 50 55 20 62 61 63 6b 65 6e 64 20 6d 69 6e 65 72 20 63 6f 6e 66 69 67 20 66 69 6c 65 } //1 CPU backend miner config file
		$a_00_2 = {70 6f 6f 6c 2e 75 73 78 6d 72 70 6f 6f 6c 2e 63 6f 6d 3a 33 33 33 33 } //1 pool.usxmrpool.com:3333
		$a_00_3 = {43 50 55 20 6d 69 6e 69 6e 67 20 63 6f 64 65 20 62 79 20 74 65 76 61 64 6f 72 20 61 6e 64 20 53 43 68 65 72 6e 79 6b 68 } //1 CPU mining code by tevador and SChernykh
		$a_00_4 = {52 61 6e 64 6f 6d 58 5f 4d 6f 6e 65 72 6f 43 6f 6e 66 69 67 } //1 RandomX_MoneroConfig
		$a_00_5 = {64 6f 6e 61 74 65 2e 78 6d 72 2d 73 74 61 6b 2e 6e 65 74 3a 31 34 34 34 31 } //1 donate.xmr-stak.net:14441
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=3
 
}