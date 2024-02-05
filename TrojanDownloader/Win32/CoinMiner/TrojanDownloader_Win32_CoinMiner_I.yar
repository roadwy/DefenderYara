
rule TrojanDownloader_Win32_CoinMiner_I{
	meta:
		description = "TrojanDownloader:Win32/CoinMiner.I,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {5c 00 76 00 72 00 66 00 42 00 71 00 } //01 00 
		$a_01_1 = {6b 00 77 00 77 00 73 00 3d 00 32 00 32 00 6c 00 71 00 76 00 6c 00 67 00 6c 00 72 00 78 00 76 00 66 00 72 00 67 00 68 00 75 00 31 00 66 00 72 00 70 00 32 00 55 00 68 00 79 00 64 00 70 00 73 00 68 00 67 00 32 00 49 00 6c 00 6f 00 68 00 76 00 32 00 66 00 6a 00 31 00 68 00 } //00 00 
	condition:
		any of ($a_*)
 
}