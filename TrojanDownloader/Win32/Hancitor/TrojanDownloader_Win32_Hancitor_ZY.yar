
rule TrojanDownloader_Win32_Hancitor_ZY{
	meta:
		description = "TrojanDownloader:Win32/Hancitor.ZY,SIGNATURE_TYPE_PEHSTR_EXT,6f 00 6f 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {f1 d5 00 fa 4c 62 cc f4 0f 0b } //0a 00 
		$a_01_1 = {6e 63 64 72 6c 65 62 } //64 00 
		$a_01_2 = {b8 01 00 00 00 c1 e0 00 8b 4d 08 0f be 14 01 83 fa 3a 75 35 8b 45 fc 0f be 08 85 c9 74 2b 8b 55 fc 0f be 02 b9 01 00 00 00 6b d1 00 8b 4d 08 0f be 14 11 3b c2 75 07 b8 01 00 00 00 eb 0d 8b 45 fc 83 c0 01 89 45 fc eb cb } //00 00 
		$a_00_3 = {5d 04 00 00 18 bb 04 80 5c 23 00 00 19 bb 04 80 00 00 01 00 04 00 0d 00 88 21 48 61 6e 63 69 74 6f 72 2e 5a 58 00 00 01 40 05 82 5c 00 04 00 78 21 00 00 64 00 64 00 01 00 00 64 00 14 01 b8 01 00 00 00 6b c8 00 c6 81 00 50 ef 14 00 68 00 20 00 00 00 00 5d 04 00 00 19 bb 04 80 5c 35 00 00 1a bb 04 80 00 00 01 00 2e 00 1f 00 42 65 } //68 61 
	condition:
		any of ($a_*)
 
}