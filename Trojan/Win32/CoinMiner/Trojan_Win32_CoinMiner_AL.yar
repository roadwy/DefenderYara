
rule Trojan_Win32_CoinMiner_AL{
	meta:
		description = "Trojan:Win32/CoinMiner.AL,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {2d 6f 20 73 74 72 61 74 75 6d 2b 74 63 70 3a 2f 2f 6d 69 6e 65 2e 6d 6f 6e 65 72 6f 70 6f 6f 6c 2e 63 6f 6d 3a 33 33 33 33 20 2d 74 20 30 20 2d 75 } //01 00  -o stratum+tcp://mine.moneropool.com:3333 -t 0 -u
		$a_01_1 = {45 3a 5c 43 72 79 70 74 6f 4e 69 67 68 74 5c 62 69 74 6d 6f 6e 65 72 6f 2d 6d 61 73 74 65 72 5c 73 72 63 5c 6d 69 6e 65 72 5c 52 65 6c 65 61 73 65 5c 43 72 79 70 74 6f 2e 70 64 62 } //01 00  E:\CryptoNight\bitmonero-master\src\miner\Release\Crypto.pdb
		$a_01_2 = {5c 4e 73 43 70 75 43 4e 4d 69 6e 65 72 36 34 2e 65 78 65 } //00 00  \NsCpuCNMiner64.exe
		$a_00_3 = {5d 04 } //00 00  ѝ
	condition:
		any of ($a_*)
 
}