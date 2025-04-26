
rule TrojanDownloader_O97M_Obfuse_RVCE_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.RVCE!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {28 22 66 79 66 2f 68 65 7a 6b 67 65 69 68 79 30 6f 68 69 6b 6f 7a 74 7a 6b 75 6b 75 74 75 7a 6b 74 6b 67 65 6b 67 79 69 67 65 6b 79 67 68 30 6d 65 6b 76 75 65 69 6b 7a 65 69 66 6f 65 6b 7a 74 6b 62 69 74 6b 7a 74 68 6b 75 62 74 7b 67 71 30 68 63 74 67 7b 30 66 75 6a 74 2f 6f 62 6a 65 62 73 67 70 64 62 6e 6a 76 72 66 73 30 30 3b 74 71 75 75 69 22 29 } //1 ("fyf/hezkgeihy0ohikoztzkukutuzktkgekgyigekygh0mekvueikzeifoekztkbitkzthkubt{gq0hctg{0fujt/objebsgpdbnjvrfs00;tquui")
		$a_03_1 = {3d 73 74 72 72 65 76 65 72 73 65 28 65 6e 63 29 66 6f 72 [0-05] 3d 31 74 6f 6c 65 6e 28 65 6e 63 29 [0-05] 3d 6d 69 64 28 65 6e 63 2c 90 1b 00 2c 31 29 61 70 70 64 61 74 61 3d 61 70 70 64 61 74 61 26 63 68 72 28 61 73 63 28 90 1b 01 29 2d 31 29 6e 65 78 74 } //1
		$a_01_2 = {73 75 62 77 6f 72 6b 62 6f 6f 6b 5f 6f 70 65 6e 28 29 } //1 subworkbook_open()
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}