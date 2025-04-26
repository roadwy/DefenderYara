
rule TrojanDownloader_O97M_Emotet_QF_MTB{
	meta:
		description = "TrojanDownloader:O97M/Emotet.QF!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {2e 43 72 65 61 74 65 28 [0-25] 20 2b 20 [0-25] 2c 20 [0-25] 2c 20 [0-25] 2c 20 [0-25] 29 } //1
		$a_03_1 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 [0-15] 28 [0-15] 20 2b 20 [0-15] 28 [0-02] 29 29 29 } //1
		$a_03_2 = {3d 20 52 65 70 6c 61 63 65 28 [0-20] 2c 20 [0-20] 2c 20 22 22 29 } //1
		$a_01_3 = {2e 53 74 6f 72 79 52 61 6e 67 65 73 28 77 64 4d 61 69 6e 54 65 78 74 53 74 6f 72 79 29 2e 44 65 6c 65 74 65 } //1 .StoryRanges(wdMainTextStory).Delete
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}