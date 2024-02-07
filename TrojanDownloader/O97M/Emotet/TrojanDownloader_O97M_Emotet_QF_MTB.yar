
rule TrojanDownloader_O97M_Emotet_QF_MTB{
	meta:
		description = "TrojanDownloader:O97M/Emotet.QF!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {2e 43 72 65 61 74 65 28 90 02 25 20 2b 20 90 02 25 2c 20 90 02 25 2c 20 90 02 25 2c 20 90 02 25 29 90 00 } //01 00 
		$a_03_1 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 90 02 15 28 90 02 15 20 2b 20 90 02 15 28 90 02 02 29 29 29 90 00 } //01 00 
		$a_03_2 = {3d 20 52 65 70 6c 61 63 65 28 90 02 20 2c 20 90 02 20 2c 20 22 22 29 90 00 } //01 00 
		$a_01_3 = {2e 53 74 6f 72 79 52 61 6e 67 65 73 28 77 64 4d 61 69 6e 54 65 78 74 53 74 6f 72 79 29 2e 44 65 6c 65 74 65 } //00 00  .StoryRanges(wdMainTextStory).Delete
	condition:
		any of ($a_*)
 
}