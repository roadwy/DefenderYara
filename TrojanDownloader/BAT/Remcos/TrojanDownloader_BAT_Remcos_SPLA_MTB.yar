
rule TrojanDownloader_BAT_Remcos_SPLA_MTB{
	meta:
		description = "TrojanDownloader:BAT/Remcos.SPLA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 05 00 00 02 00 "
		
	strings :
		$a_03_0 = {0d 07 08 6f 90 01 03 0a 08 6f 90 01 03 0a 16 6a 31 39 08 6f 90 01 03 0a 13 04 08 6f 90 01 03 0a 09 11 04 16 11 04 8e 69 6f 90 01 03 0a 09 6f 90 01 03 0a 16 6a 31 14 11 04 2c 10 16 2d bd 09 6f 90 01 03 0a 13 05 18 2c c9 de 54 90 00 } //01 00 
		$a_01_1 = {6e 00 6f 00 69 00 74 00 68 00 61 00 74 00 68 00 6f 00 61 00 6e 00 67 00 67 00 69 00 61 00 74 00 6e 00 2e 00 63 00 6f 00 6d 00 2f 00 6c 00 6f 00 61 00 64 00 65 00 72 00 2f 00 75 00 70 00 6c 00 6f 00 61 00 64 00 73 00 2f 00 6e 00 6f 00 69 00 63 00 6f 00 6e 00 5f 00 56 00 6a 00 61 00 65 00 78 00 73 00 6f 00 71 00 2e 00 62 00 6d 00 70 00 } //01 00  noithathoanggiatn.com/loader/uploads/noicon_Vjaexsoq.bmp
		$a_01_2 = {4c 00 72 00 76 00 75 00 6e 00 64 00 62 00 2e 00 51 00 76 00 67 00 75 00 68 00 6e 00 6e 00 76 00 67 00 71 00 68 00 6e 00 73 00 79 00 } //01 00  Lrvundb.Qvguhnnvgqhnsy
		$a_01_3 = {4d 00 6e 00 74 00 6a 00 6b 00 65 00 77 00 62 00 72 00 74 00 } //01 00  Mntjkewbrt
		$a_01_4 = {50 00 71 00 74 00 78 00 66 00 64 00 65 00 6a 00 6f 00 79 00 6e 00 78 00 66 00 71 00 75 00 6e 00 70 00 72 00 74 00 71 00 67 00 } //00 00  Pqtxfdejoynxfqunprtqg
	condition:
		any of ($a_*)
 
}