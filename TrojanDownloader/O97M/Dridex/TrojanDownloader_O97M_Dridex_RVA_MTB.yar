
rule TrojanDownloader_O97M_Dridex_RVA_MTB{
	meta:
		description = "TrojanDownloader:O97M/Dridex.RVA!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {52 65 70 6c 61 63 65 28 22 68 74 74 70 73 3a 2f 2f 73 75 72 75 73 74 6f 72 65 2e 63 6f 6d 2f 69 6d 61 67 65 59 39 61 3c 25 37 2f 63 61 63 68 65 2f 63 61 74 61 6c 6f 67 2f 64 65 6d 6f 2f 62 61 6e 6e 65 72 73 59 39 61 3c 25 37 2f 68 30 64 44 38 54 32 61 4e 52 7a 2e 70 68 70 22 2c 20 22 59 39 61 3c 25 37 22 2c 20 22 22 29 } //01 00  Replace("https://surustore.com/imageY9a<%7/cache/catalog/demo/bannersY9a<%7/h0dD8T2aNRz.php", "Y9a<%7", "")
		$a_01_1 = {27 72 75 6e 64 6c 6c 33 4c 5e 4f 3c 24 48 3e 32 2e 65 78 65 20 22 2c 20 22 4c 5e 4f 3c 24 48 3e 22 2c } //01 00  'rundll3L^O<$H>2.exe ", "L^O<$H>",
		$a_01_2 = {3d 20 52 65 70 6c 61 63 65 28 22 57 2c 3c 36 64 34 4f 37 73 63 72 69 2c 3c 36 64 34 4f 37 70 74 2e 53 68 2c 3c 36 64 34 4f 37 65 6c 6c 22 2c 20 22 2c 3c 36 64 34 4f 37 22 2c 20 22 22 29 } //01 00  = Replace("W,<6d4O7scri,<6d4O7pt.Sh,<6d4O7ell", ",<6d4O7", "")
		$a_01_3 = {45 6e 76 69 72 6f 6e 28 6d 79 74 68 6f 70 6f 65 73 65 73 62 61 63 6b 2e 63 6f 72 70 75 6c 65 6e 74 6c 79 69 63 65 62 28 75 6e 70 61 70 65 72 61 6e 6f 64 6f 6e 74 69 29 29 } //01 00  Environ(mythopoesesback.corpulentlyiceb(unpaperanodonti))
		$a_01_4 = {2e 4f 70 65 6e 20 77 69 67 67 6c 65 72 73 63 6f 77 61 72 64 6c 2e 62 72 6f 6e 7a 69 74 65 73 63 79 63 6c 61 7a } //00 00  .Open wigglerscowardl.bronzitescyclaz
	condition:
		any of ($a_*)
 
}