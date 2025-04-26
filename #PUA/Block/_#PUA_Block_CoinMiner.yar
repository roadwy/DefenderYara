
rule _#PUA_Block_CoinMiner{
	meta:
		description = "!#PUA:Block:CoinMiner,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 05 00 00 "
		
	strings :
		$a_80_0 = {62 66 67 6d 69 6e 65 72 2e 65 78 65 } //bfgminer.exe  1
		$a_80_1 = {73 74 72 61 74 75 6d 5f 74 68 72 65 61 64 } //stratum_thread  1
		$a_80_2 = {63 67 6d 69 6e 65 72 5f 70 6f 6f 6c 5f 73 74 61 74 73 } //cgminer_pool_stats  1
		$a_80_3 = {63 67 6d 69 6e 65 72 5f 73 74 61 74 73 } //cgminer_stats  1
		$a_80_4 = {63 6f 69 6e 62 61 73 65 } //coinbase  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1) >=3
 
}
rule _#PUA_Block_CoinMiner_2{
	meta:
		description = "!#PUA:Block:CoinMiner,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {63 72 79 70 74 6f 6e 6f 74 65 5f 66 6f 72 6d 61 74 5f 75 74 69 6c 73 2e 63 70 70 } //1 cryptonote_format_utils.cpp
		$a_01_1 = {53 74 6f 70 20 6d 69 6e 69 6e 67 } //1 Stop mining
		$a_01_2 = {6d 69 6e 65 72 5f 63 6f 6e 66 2e 6a 73 6f 6e } //1 miner_conf.json
		$a_01_3 = {63 72 79 70 74 6f 6e 6f 74 65 5f 70 72 6f 74 6f 63 6f 6c 5f 68 61 6e 64 6c 65 72 2e 69 6e 6c } //1 cryptonote_protocol_handler.inl
		$a_01_4 = {6d 69 6e 65 72 2e 63 70 70 } //1 miner.cpp
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}
rule _#PUA_Block_CoinMiner_3{
	meta:
		description = "!#PUA:Block:CoinMiner,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {71 74 2f 63 72 6f 77 64 63 6f 69 6e 2e 63 70 70 } //1 qt/crowdcoin.cpp
		$a_01_1 = {63 72 6f 77 64 63 6f 69 6e 64 2e 70 69 64 } //1 crowdcoind.pid
		$a_01_2 = {31 30 42 69 74 63 6f 69 6e 47 55 49 } //1 10BitcoinGUI
		$a_01_3 = {32 72 65 63 65 69 76 65 64 50 61 79 6d 65 6e 74 52 65 71 75 65 73 74 28 53 65 6e 64 43 6f 69 6e 73 52 65 63 69 70 69 65 6e 74 29 } //1 2receivedPaymentRequest(SendCoinsRecipient)
		$a_01_4 = {32 72 65 63 65 69 76 65 64 55 52 49 28 51 53 74 72 69 6e 67 29 } //1 2receivedURI(QString)
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}
rule _#PUA_Block_CoinMiner_4{
	meta:
		description = "!#PUA:Block:CoinMiner,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {53 4f 4c 56 45 44 20 25 64 20 42 4c 4f 43 4b 25 73 21 } //1 SOLVED %d BLOCK%s!
		$a_01_1 = {49 6e 76 61 6c 69 64 20 62 69 74 62 75 72 6e 65 72 2d 76 6f 6c 74 61 67 65 20 25 64 20 6d 75 73 74 20 62 65 20 25 64 6d 76 20 2d 20 25 64 6d 76 } //1 Invalid bitburner-voltage %d must be %dmv - %dmv
		$a_01_2 = {63 6f 69 6e 62 61 73 65 74 78 6e } //1 coinbasetxn
		$a_01_3 = {43 6f 6e 6e 65 63 74 65 64 20 74 6f 20 6d 75 6c 74 69 70 6c 65 20 70 6f 6f 6c 73 20 77 69 74 68 25 73 20 62 6c 6f 63 6b 20 63 68 61 6e 67 65 20 6e 6f 74 69 66 79 } //1 Connected to multiple pools with%s block change notify
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}
rule _#PUA_Block_CoinMiner_5{
	meta:
		description = "!#PUA:Block:CoinMiner,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 0a 00 00 "
		
	strings :
		$a_01_0 = {55 73 61 67 65 3a 20 6d 69 6e 65 72 64 20 5b 4f 50 54 49 4f 4e 53 5d } //1 Usage: minerd [OPTIONS]
		$a_01_1 = {6d 69 6e 65 72 64 20 2d 2d 68 65 6c 70 } //1 minerd --help
		$a_01_2 = {63 70 75 6d 69 6e 65 72 } //1 cpuminer
		$a_01_3 = {4c 4f 4e 47 50 4f 4c 4c 20 64 65 74 65 63 74 65 64 20 6e 65 77 20 62 6c 6f 63 6b } //1 LONGPOLL detected new block
		$a_01_4 = {6d 69 6e 69 6e 67 2e 73 75 62 6d 69 74 } //1 mining.submit
		$a_01_5 = {73 74 72 61 74 75 6d 2b 74 63 70 3a 2f 2f } //1 stratum+tcp://
		$a_01_6 = {22 6d 65 74 68 6f 64 22 3a 20 22 6d 69 6e 69 6e 67 2e 73 75 62 73 63 72 69 62 65 22 } //2 "method": "mining.subscribe"
		$a_01_7 = {22 6d 65 74 68 6f 64 22 3a 20 22 6d 69 6e 69 6e 67 2e 61 75 74 68 6f 72 69 7a 65 22 } //2 "method": "mining.authorize"
		$a_01_8 = {22 61 67 65 6e 74 22 3a 20 22 63 70 75 6d 69 6e 65 72 2d 6d 75 6c 74 69 2f 30 2e 31 22 } //2 "agent": "cpuminer-multi/0.1"
		$a_01_9 = {6d 69 6e 69 6e 67 2e 73 65 74 5f 64 69 66 66 69 63 75 6c 74 79 } //1 mining.set_difficulty
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*2+(#a_01_7  & 1)*2+(#a_01_8  & 1)*2+(#a_01_9  & 1)*1) >=3
 
}
rule _#PUA_Block_CoinMiner_6{
	meta:
		description = "!#PUA:Block:CoinMiner,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {67 65 6e 65 73 69 73 20 62 6c 6f 63 6b 20 72 65 77 61 72 64 73 } //1 genesis block rewards
		$a_01_1 = {46 61 69 6c 65 64 20 74 6f 20 63 6f 6e 73 74 72 75 63 74 20 6d 69 6e 65 72 20 74 78 } //1 Failed to construct miner tx
		$a_01_2 = {57 61 6c 6c 65 74 } //1 Wallet
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
rule _#PUA_Block_CoinMiner_7{
	meta:
		description = "!#PUA:Block:CoinMiner,SIGNATURE_TYPE_PEHSTR,04 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {70 6f 6f 6c 73 74 61 74 65 2e 62 69 6e } //1 poolstate.bin
		$a_01_1 = {6d 69 6e 65 72 5f 74 78 } //1 miner_tx
		$a_01_2 = {67 65 74 77 61 6c 6c 65 74 73 79 6e 63 64 61 74 61 } //1 getwalletsyncdata
		$a_01_3 = {77 61 6c 6c 65 74 5f 61 64 64 72 65 73 73 } //1 wallet_address
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}
rule _#PUA_Block_CoinMiner_8{
	meta:
		description = "!#PUA:Block:CoinMiner,SIGNATURE_TYPE_PEHSTR,09 00 09 00 09 00 00 "
		
	strings :
		$a_01_0 = {6a 6f 62 5f 69 64 } //1 job_id
		$a_01_1 = {77 6f 72 6b 65 72 2d 69 64 } //1 worker-id
		$a_01_2 = {22 6e 69 63 65 68 61 73 68 22 3a } //1 "nicehash":
		$a_01_3 = {22 70 61 73 73 22 3a 20 22 } //1 "pass": "
		$a_01_4 = {22 75 73 65 72 22 3a 20 22 } //1 "user": "
		$a_01_5 = {22 75 72 6c 22 3a 20 22 } //1 "url": "
		$a_01_6 = {22 64 6f 6e 61 74 65 2d 6f 76 65 72 2d 70 72 6f 78 79 22 3a 20 31 2c } //1 "donate-over-proxy": 1,
		$a_01_7 = {63 70 75 2d 61 66 66 69 6e 69 74 79 } //1 cpu-affinity
		$a_01_8 = {70 6f 6f 6c 73 } //1 pools
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1) >=9
 
}