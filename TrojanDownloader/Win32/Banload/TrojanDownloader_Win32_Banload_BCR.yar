
rule TrojanDownloader_Win32_Banload_BCR{
	meta:
		description = "TrojanDownloader:Win32/Banload.BCR,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {36 32 36 31 37 33 36 35 37 34 32 45 36 35 37 38 36 35 } //01 00  62617365742E657865
		$a_01_1 = {36 39 36 44 36 35 37 34 37 32 36 46 32 45 36 35 37 38 36 35 } //01 00  696D6574726F2E657865
		$a_01_2 = {32 45 37 41 36 39 37 30 } //01 00  2E7A6970
		$a_01_3 = {54 56 61 6d 70 69 72 6f } //00 00  TVampiro
		$a_00_4 = {80 10 } //00 00 
	condition:
		any of ($a_*)
 
}