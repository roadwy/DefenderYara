
rule TrojanDownloader_BAT_SnakeKeyLogger_RDF_MTB{
	meta:
		description = "TrojanDownloader:BAT/SnakeKeyLogger.RDF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {39 36 33 32 62 61 33 35 2d 35 31 36 37 2d 34 33 32 66 2d 61 37 30 37 2d 37 32 39 63 35 37 39 34 33 34 32 61 } //01 00  9632ba35-5167-432f-a707-729c5794342a
		$a_01_1 = {2f 00 2f 00 31 00 39 00 32 00 2e 00 33 00 2e 00 32 00 36 00 2e 00 31 00 33 00 35 00 2f 00 75 00 6f 00 2f 00 43 00 75 00 69 00 6a 00 6f 00 2e 00 64 00 6c 00 6c 00 } //01 00  //192.3.26.135/uo/Cuijo.dll
		$a_01_2 = {4a 00 74 00 76 00 6b 00 68 00 6d 00 69 00 66 00 73 00 62 00 6d 00 62 00 6d 00 73 00 6e 00 76 00 78 00 76 00 77 00 77 00 6c 00 77 00 2e 00 55 00 63 00 6d 00 67 00 61 00 69 00 66 00 74 00 64 00 7a 00 67 00 64 00 63 00 73 00 61 00 75 00 78 00 71 00 63 00 73 00 6c 00 } //01 00  Jtvkhmifsbmbmsnvxvwwlw.Ucmgaiftdzgdcsauxqcsl
		$a_01_3 = {4f 00 64 00 77 00 61 00 6c 00 73 00 69 00 74 00 70 00 62 00 68 00 71 00 78 00 75 00 75 00 67 00 6d 00 71 00 66 00 6f 00 70 00 6a 00 6d 00 } //00 00  Odwalsitpbhqxuugmqfopjm
	condition:
		any of ($a_*)
 
}