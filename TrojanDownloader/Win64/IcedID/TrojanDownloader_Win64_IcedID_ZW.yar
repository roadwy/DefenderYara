
rule TrojanDownloader_Win64_IcedID_ZW{
	meta:
		description = "TrojanDownloader:Win64/IcedID.ZW,SIGNATURE_TYPE_PEHSTR_EXT,65 00 65 00 02 00 00 01 00 "
		
	strings :
		$a_00_0 = {f1 d5 00 fa 4c 62 cc f4 0f 0b } //64 00 
		$a_03_1 = {83 e2 03 41 83 e0 03 90 02 01 8a 90 01 03 90 02 01 02 90 01 03 90 02 01 32 90 02 02 42 8b 4c 90 01 02 41 88 04 1b 83 e1 07 8b 44 90 01 02 49 ff c3 d3 c8 ff c0 89 44 90 01 02 83 e0 07 8a c8 42 8b 44 90 01 02 d3 c8 ff c0 42 89 44 90 01 02 48 8b 90 02 03 4c 3b 90 02 03 73 90 00 } //00 00 
		$a_00_2 = {5d 04 00 00 44 a0 04 80 5c 23 00 00 46 a0 04 80 00 00 01 00 04 00 0d 00 88 21 5a 4c 6f 61 64 65 72 21 4d 53 52 00 00 02 40 05 82 5c 00 04 00 67 16 00 00 2e 1e 78 11 20 2b cb cd fd 54 45 ae 00 b4 02 00 01 20 bb 50 88 d3 67 16 00 00 ca ae 47 ee f8 e4 5e d0 73 b0 db 09 00 b4 02 00 01 20 f7 f6 51 d6 5d } //04 00 
	condition:
		any of ($a_*)
 
}