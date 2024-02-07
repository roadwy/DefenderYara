
rule TrojanDownloader_Win32_Small_KZ{
	meta:
		description = "TrojanDownloader:Win32/Small.KZ,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {77 77 77 2e 33 36 30 68 61 6f 77 61 6e 2e 63 6e } //01 00  www.360haowan.cn
		$a_00_1 = {6d 61 74 63 36 } //01 00  matc6
		$a_03_2 = {83 c4 48 33 c9 80 90 01 03 00 8d 90 01 03 75 03 c6 00 30 41 83 f9 0c 7c ec 90 00 } //01 00 
		$a_03_3 = {83 c4 1c 85 c0 75 21 68 88 13 00 00 ff 15 90 01 02 40 00 8d 45 90 01 01 50 8d 85 90 01 02 ff ff 56 50 e8 90 01 02 ff ff 83 c4 0c eb db 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}