
rule TrojanDownloader_Win32_Waledac_AJ{
	meta:
		description = "TrojanDownloader:Win32/Waledac.AJ,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 05 00 00 01 00 "
		
	strings :
		$a_03_0 = {c7 04 24 00 00 20 00 e8 90 01 02 ff ff a3 90 01 04 c7 04 24 00 90 90 01 00 90 00 } //01 00 
		$a_03_1 = {83 7c 24 10 03 7d 0c 68 90 01 04 8d 44 24 28 50 ff d6 ff 44 24 10 c1 6c 24 14 08 83 7c 24 10 04 7c 90 00 } //01 00 
		$a_03_2 = {8d 42 01 33 d2 f7 74 24 18 39 1c 95 90 01 04 74 90 01 01 8d 04 95 90 01 04 8b 08 89 18 88 5c 24 24 33 c0 8d 7c 24 25 90 00 } //01 00 
		$a_02_3 = {2f 31 2e 30 0d 0a 90 02 10 74 65 6d 70 00 90 00 } //01 00 
		$a_03_4 = {50 ff d6 e8 90 01 04 8b c8 33 c0 33 db 88 5d f0 8d 7d f1 ab ab 66 ab aa 6a 0b 8d 45 f0 50 51 e8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}