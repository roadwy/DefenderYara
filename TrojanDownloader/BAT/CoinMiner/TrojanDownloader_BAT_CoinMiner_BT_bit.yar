
rule TrojanDownloader_BAT_CoinMiner_BT_bit{
	meta:
		description = "TrojanDownloader:BAT/CoinMiner.BT!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 05 00 00 "
		
	strings :
		$a_03_0 = {5c 46 6f 72 6d 31 5c 46 6f 72 6d 31 5c 6f 62 6a 5c (44 65 62 75 67|52 65 6c 65 61 73 65) 5c 46 6f 72 6d 31 2e 70 64 62 } //1
		$a_01_1 = {63 00 68 00 62 00 72 00 65 00 } //1 chbre
		$a_01_2 = {69 00 6e 00 6d 00 64 00 77 00 } //1 inmdw
		$a_01_3 = {71 00 71 00 71 00 2e 00 69 00 6e 00 6e 00 6f 00 63 00 72 00 61 00 66 00 74 00 2e 00 63 00 6c 00 6f 00 75 00 64 00 2f 00 70 00 69 00 77 00 69 00 6b 00 2e 00 70 00 68 00 70 00 } //2 qqq.innocraft.cloud/piwik.php
		$a_01_4 = {6e 00 61 00 62 00 72 00 6f 00 77 00 73 00 65 00 72 00 2e 00 63 00 6f 00 6d 00 } //2 nabrowser.com
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2) >=3
 
}