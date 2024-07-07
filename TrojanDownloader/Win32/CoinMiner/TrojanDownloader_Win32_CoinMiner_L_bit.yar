
rule TrojanDownloader_Win32_CoinMiner_L_bit{
	meta:
		description = "TrojanDownloader:Win32/CoinMiner.L!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {68 74 74 70 3a 2f 2f 38 32 2e 31 34 36 2e 35 34 2e 31 38 37 2f 90 02 30 2e 7a 69 70 90 00 } //1
		$a_03_1 = {2d 6c 20 7a 65 63 2e 90 02 20 20 2d 75 20 90 02 20 20 2d 70 20 78 90 00 } //1
		$a_03_2 = {68 74 74 70 3a 2f 2f 90 02 30 2e 6f 6e 69 6f 6e 2f 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}