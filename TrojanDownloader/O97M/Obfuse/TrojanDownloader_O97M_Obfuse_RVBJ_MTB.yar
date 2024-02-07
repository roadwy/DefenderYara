
rule TrojanDownloader_O97M_Obfuse_RVBJ_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.RVBJ!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {61 62 6d 61 67 71 61 63 77 62 6d 61 68 6d 61 7a 61 62 6d 61 63 61 61 70 71 61 67 61 63 69 61 7a 67 62 7a 61 67 79 61 7a 61 62 6e 61 67 67 61 7a 67 62 6b 61 67 71 61 7a 67 62 6e 61 67 67 61 69 67 61 37 61 61 3d 3d } //01 00  abmagqacwbmahmazabmacaapqagaciazgbzagyazabnaggazgbkagqazgbnaggaiga7aa==
		$a_01_1 = {73 68 65 6c 6c 28 6e 72 61 70 6f 69 6e 66 2c 34 2f 38 2a 73 69 6e 28 30 29 29 27 30 30 30 30 65 6e 64 73 75 62 } //01 00  shell(nrapoinf,4/8*sin(0))'0000endsub
		$a_01_2 = {64 6f 63 75 6d 65 6e 74 5f 6f 70 65 6e 28 29 63 61 6c 6c 73 61 71 65 76 76 68 79 69 65 6e 64 73 75 62 } //00 00  document_open()callsaqevvhyiendsub
	condition:
		any of ($a_*)
 
}