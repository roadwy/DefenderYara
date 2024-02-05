
rule TrojanDownloader_Win64_IcedID_ZV{
	meta:
		description = "TrojanDownloader:Win64/IcedID.ZV,SIGNATURE_TYPE_PEHSTR_EXT,65 00 65 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {f1 d5 00 fa 4c 62 cc f4 0f 0b } //64 00 
		$a_01_1 = {8d 81 59 2e 00 00 d1 c8 d1 c8 c1 c8 02 35 1d 15 00 00 c1 c0 02 d1 c0 c3 } //00 00 
		$a_00_2 = {5d 04 00 00 8f a9 04 80 5c 3a 00 00 90 a9 04 80 00 00 01 00 04 00 24 00 54 72 6f 6a 61 6e 44 6f 77 6e 6c 6f 61 64 65 72 3a 57 69 6e 36 34 2f 49 63 65 64 49 44 2e 5a 56 21 73 6d 73 00 00 01 40 05 82 5c 00 04 00 ce 09 00 00 f4 0a 8a cb 78 35 00 00 7b 5d 04 00 00 90 a9 04 80 5c 33 00 00 92 a9 04 80 00 } //00 01 
	condition:
		any of ($a_*)
 
}