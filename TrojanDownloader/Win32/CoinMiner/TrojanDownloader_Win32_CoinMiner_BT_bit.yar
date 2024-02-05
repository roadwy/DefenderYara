
rule TrojanDownloader_Win32_CoinMiner_BT_bit{
	meta:
		description = "TrojanDownloader:Win32/CoinMiner.BT!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_11_0 = {74 70 68 6f 73 74 69 6e 67 2e 70 77 2f 01 } //00 31 
		$a_52_1 = {4e 44 4f 4d 3d 43 72 65 61 74 65 4f 62 6a 65 63 74 } //28 22 
		$a_63_2 = {69 70 74 69 6e 67 2e 46 69 6c 65 53 79 73 74 65 6d 4f 62 6a 65 63 74 22 29 01 00 31 11 52 41 4e 44 4f 4d 3d 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 57 69 6e 48 74 74 70 2e 57 69 6e 48 74 74 70 52 65 71 75 65 73 74 2e 35 2e 31 22 29 00 00 5d 04 00 } //00 fa 
	condition:
		any of ($a_*)
 
}