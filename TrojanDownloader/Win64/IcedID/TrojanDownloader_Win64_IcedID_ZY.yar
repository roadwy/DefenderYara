
rule TrojanDownloader_Win64_IcedID_ZY{
	meta:
		description = "TrojanDownloader:Win64/IcedID.ZY,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {30 31 32 33 34 35 36 37 38 39 41 42 43 44 45 46 } //01 00 
		$a_01_1 = {42 8a 04 02 02 c2 48 ff c2 c0 c0 03 0f b6 c8 8b c1 83 e1 0f 48 c1 e8 04 42 0f be 04 18 66 42 89 04 53 42 0f be 0c 19 66 42 89 4c 53 02 49 83 c2 02 49 3b d1 72 ca } //01 00 
		$a_01_2 = {0f b6 c8 49 ff c0 8b c1 83 e1 0f 48 c1 e8 04 0f be 04 10 66 43 89 04 4b 0f be 04 11 66 43 89 44 4b 02 49 83 c1 02 41 8a 00 84 c0 75 d3 } //00 00 
	condition:
		any of ($a_*)
 
}