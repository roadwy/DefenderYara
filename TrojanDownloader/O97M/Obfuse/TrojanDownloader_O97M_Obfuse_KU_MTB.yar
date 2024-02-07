
rule TrojanDownloader_O97M_Obfuse_KU_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.KU!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {4d 6e 75 65 6a 77 72 20 4e 4d 56 31 2e 54 65 78 74 2c 20 41 72 72 61 79 28 31 2c 20 32 2c 20 33 2c 20 34 29 2c 20 4e 4d 56 32 2e 54 65 78 74 } //01 00  Mnuejwr NMV1.Text, Array(1, 2, 3, 4), NMV2.Text
		$a_01_1 = {46 75 6e 63 74 69 6f 6e 20 4d 6e 75 65 6a 77 72 28 75 65 6e 6a 6b 36 36 2c 20 62 64 6a 77 6a 37 37 2c 20 69 72 77 65 68 38 38 29 } //01 00  Function Mnuejwr(uenjk66, bdjwj77, irweh88)
		$a_01_2 = {53 75 62 20 56 62 65 72 77 28 76 62 66 29 } //01 00  Sub Vberw(vbf)
		$a_01_3 = {47 67 6f 70 46 72 6d 2e 53 68 6f 77 } //01 00  GgopFrm.Show
		$a_01_4 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 20 30 2c 20 6d 69 65 6e 35 35 2c 20 6d 65 6a 6e 77 33 33 2c 20 30 2c 20 30 } //00 00  URLDownloadToFile 0, mien55, mejnw33, 0, 0
	condition:
		any of ($a_*)
 
}