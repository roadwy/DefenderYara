
rule VirTool_Win32_CoinMiner_A_sms{
	meta:
		description = "VirTool:Win32/CoinMiner.A!sms,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0a 00 00 01 00 "
		
	strings :
		$a_01_0 = {58 4d 52 49 47 5f 48 4f 53 54 4e 41 4d 45 } //01 00  XMRIG_HOSTNAME
		$a_01_1 = {58 4d 52 49 47 5f 49 4e 43 4c 55 44 45 5f 52 41 4e 44 4f 4d 5f 4d 41 54 48 } //01 00  XMRIG_INCLUDE_RANDOM_MATH
		$a_01_2 = {64 6f 6e 61 74 65 2d 6f 76 65 72 2d 70 72 6f 78 79 } //01 00  donate-over-proxy
		$a_01_3 = {6e 69 63 65 68 61 73 68 } //01 00  nicehash
		$a_01_4 = {73 74 72 61 74 75 6d 2b 73 73 6c 3a 2f 2f } //01 00  stratum+ssl://
		$a_01_5 = {70 6f 6f 6c 5f 77 61 6c 6c 65 74 } //01 00  pool_wallet
		$a_01_6 = {77 6f 72 6b 65 72 5f 69 64 } //01 00  worker_id
		$a_01_7 = {6d 69 6e 69 6e 67 2e 73 75 62 6d 69 74 } //01 00  mining.submit
		$a_01_8 = {6d 61 78 2d 63 70 75 2d 75 73 61 67 65 } //01 00  max-cpu-usage
		$a_01_9 = {57 69 6e 52 69 6e 67 30 20 64 72 69 76 65 72 } //01 00  WinRing0 driver
	condition:
		any of ($a_*)
 
}