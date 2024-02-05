
rule TrojanDownloader_BAT_Tiny_AP_MTB{
	meta:
		description = "TrojanDownloader:BAT/Tiny.AP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,12 00 0e 00 05 00 00 0a 00 "
		
	strings :
		$a_02_0 = {0a 0d 09 09 6f 90 01 03 0a 72 90 01 03 70 72 90 01 03 70 72 90 01 03 70 6f 90 01 03 0a 18 8d 90 01 03 01 13 05 11 05 16 72 90 01 03 70 a2 11 05 14 14 90 00 } //04 00 
		$a_80_1 = {40 40 21 21 23 23 24 24 25 25 5e 5e 26 26 5c 7c 7c 4c 40 40 21 21 23 23 24 24 25 25 5e 5e 26 26 5c 7c 7c 6f 40 40 21 21 23 23 24 24 25 25 5e 5e 26 26 5c 7c 7c 61 40 40 21 21 23 23 24 24 25 25 5e 5e 26 26 5c 7c 7c 64 } //@@!!##$$%%^^&&\||L@@!!##$$%%^^&&\||o@@!!##$$%%^^&&\||a@@!!##$$%%^^&&\||d  04 00 
		$a_80_2 = {40 40 21 21 23 23 24 24 25 25 5e 5e 26 26 5c 7c 7c 49 40 40 21 21 23 23 24 24 25 25 5e 5e 26 26 5c 7c 7c 6e 40 40 21 21 23 23 24 24 25 25 5e 5e 26 26 5c 7c 7c 76 40 40 21 21 23 23 24 24 25 25 5e 5e 26 26 5c 7c 7c 6f 40 40 21 21 23 23 24 24 25 25 5e 5e 26 26 5c 7c 7c 6b 40 40 21 21 23 23 24 24 25 25 5e 5e 26 26 5c 7c 7c 65 } //@@!!##$$%%^^&&\||I@@!!##$$%%^^&&\||n@@!!##$$%%^^&&\||v@@!!##$$%%^^&&\||o@@!!##$$%%^^&&\||k@@!!##$$%%^^&&\||e  03 00 
		$a_80_3 = {40 40 21 21 23 23 24 24 25 25 5e 5e 26 26 5c 7c 7c } //@@!!##$$%%^^&&\||  03 00 
		$a_80_4 = {44 6f 77 6e 6c 6f 61 64 44 61 74 61 } //DownloadData  00 00 
	condition:
		any of ($a_*)
 
}