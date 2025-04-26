
rule TrojanDownloader_Win32_CoinMiner_K_bit{
	meta:
		description = "TrojanDownloader:Win32/CoinMiner.K!bit,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {74 72 61 63 6b 69 6e 67 2e 68 75 69 6a 61 6e 67 2e 63 6f 6d 2f 61 70 69 2e 70 68 70 } //1 tracking.huijang.com/api.php
		$a_01_1 = {6e 76 73 72 76 63 33 32 2e 65 78 65 00 72 65 61 6c 73 63 68 65 64 2e 65 78 65 00 6a 75 73 63 68 65 64 2e 65 78 65 00 6d 63 73 68 69 65 6c 64 2e 65 78 65 } //1
		$a_03_2 = {c7 04 24 00 00 00 00 e8 0a 46 02 00 89 04 24 e8 0a 46 02 00 e8 0d 46 02 00 b9 05 00 00 00 89 5c 24 ?? 8d 9d ?? ?? ?? ?? 89 1c 24 99 f7 f9 8b 04 95 ?? ?? ?? ?? 89 44 24 ?? ff 15 1c 54 43 00 } //1
		$a_01_3 = {25 73 3a 2f 2f 25 73 25 73 25 73 3a 25 68 75 25 73 25 73 25 73 } //1 %s://%s%s%s:%hu%s%s%s
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}