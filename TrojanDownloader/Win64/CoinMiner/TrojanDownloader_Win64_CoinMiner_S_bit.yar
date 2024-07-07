
rule TrojanDownloader_Win64_CoinMiner_S_bit{
	meta:
		description = "TrojanDownloader:Win64/CoinMiner.S!bit,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {67 00 69 00 74 00 68 00 75 00 62 00 2e 00 63 00 6f 00 6d 00 2f 00 6e 00 69 00 63 00 65 00 68 00 61 00 73 00 68 00 2f 00 6e 00 68 00 65 00 71 00 6d 00 69 00 6e 00 65 00 72 00 2f 00 72 00 65 00 6c 00 65 00 61 00 73 00 65 00 73 00 2f 00 64 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 2f 00 } //1 github.com/nicehash/nheqminer/releases/download/
		$a_01_1 = {5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5f 00 78 00 36 00 34 00 5f 00 6e 00 68 00 65 00 71 00 6d 00 69 00 6e 00 65 00 72 00 2d 00 35 00 63 00 5c 00 5a 00 63 00 61 00 73 00 68 00 2e 00 65 00 78 00 65 00 } //1 \Windows_x64_nheqminer-5c\Zcash.exe
		$a_01_2 = {7a 00 65 00 63 00 2d 00 65 00 75 00 31 00 2e 00 6e 00 61 00 6e 00 6f 00 70 00 6f 00 6f 00 6c 00 2e 00 6f 00 72 00 67 00 3a 00 } //1 zec-eu1.nanopool.org:
		$a_01_3 = {53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 5c 00 52 00 75 00 6e 00 } //1 Software\Microsoft\Windows\CurrentVersion\Run
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}