
rule TrojanDownloader_BAT_Seraph_D_MTB{
	meta:
		description = "TrojanDownloader:BAT/Seraph.D!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 04 00 00 0a 00 "
		
	strings :
		$a_02_0 = {20 e7 03 00 00 2b 3c 00 2b 40 16 2d ee 17 59 2b 3c 18 2c 08 00 2b 39 16 fe 03 2b 37 16 2d e8 2b 35 2d dc 2b 34 2b 39 72 90 01 03 70 28 90 01 03 0a 16 2d c4 00 1a 2c c0 07 6f 90 01 03 0a 00 2a 0a 2b ba 28 90 01 03 0a 2b bd 06 2b bd 0a 2b c1 06 2b c4 0c 2b c6 08 2b c8 90 00 } //01 00 
		$a_81_1 = {53 70 6f 74 69 66 79 } //01 00 
		$a_81_2 = {41 6e 69 6d 61 6c 73 20 72 75 6e } //01 00 
		$a_81_3 = {48 75 6d 61 6e 73 20 72 75 6e } //00 00 
	condition:
		any of ($a_*)
 
}