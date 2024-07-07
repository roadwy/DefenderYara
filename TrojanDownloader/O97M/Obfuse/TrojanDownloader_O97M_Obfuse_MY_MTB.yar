
rule TrojanDownloader_O97M_Obfuse_MY_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.MY!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {53 75 62 20 4e 6a 69 6f 6a 77 71 65 68 71 77 28 6d 6e 77 75 69 75 62 68 32 32 2c 20 6d 69 69 77 74 68 62 33 33 2c 20 75 69 77 68 65 72 75 72 34 34 29 } //1 Sub Njiojwqehqw(mnwuiubh22, miiwthb33, uiwherur44)
		$a_01_1 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 20 30 2c 20 6d 69 69 77 74 68 62 33 33 2c 20 6d 6e 77 75 69 75 62 68 32 32 2c 20 30 2c 20 30 } //1 URLDownloadToFile 0, miiwthb33, mnwuiubh22, 0, 0
		$a_01_2 = {53 68 65 6c 6c 20 65 72 66 66 76 65 72 } //1 Shell erffver
		$a_01_3 = {46 75 69 6e 72 35 36 36 20 74 31 2c 20 74 32 2c 20 38 37 34 2c 20 22 79 67 66 68 35 33 34 66 67 68 68 67 22 } //1 Fuinr566 t1, t2, 874, "ygfh534fghhg"
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}