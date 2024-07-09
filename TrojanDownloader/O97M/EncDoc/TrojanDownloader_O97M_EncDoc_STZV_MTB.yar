
rule TrojanDownloader_O97M_EncDoc_STZV_MTB{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.STZV!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {52 65 70 6c 61 63 65 28 22 43 3a 5c 55 73 65 72 73 5c 50 75 62 67 39 38 37 36 31 72 69 63 5c 62 65 67 39 38 37 36 31 72 2e 67 39 38 37 36 31 72 6e 6b 22 2c 20 22 67 39 38 37 36 31 72 22 2c 20 22 6c 22 29 } //1 Replace("C:\Users\Pubg98761ric\beg98761r.g98761rnk", "g98761r", "l")
		$a_03_1 = {67 6f 64 6b 6e 6f 77 73 20 3d 20 52 65 70 6c 61 63 65 28 22 63 6d 64 20 2f 63 20 70 6f 77 5e [0-1f] 72 73 5e [0-1f] 6c 6c 2f 57 20 30 31 20 63 5e 75 5e 72 6c 20 68 74 74 5e 70 73 3a 2f 2f 74 72 61 6e 73 66 [0-1f] 72 2e 73 68 2f [0-1f] [0-1f] 2f [0-1f] 2e [0-1f] 5e [0-1f] 20 2d 6f 20 22 20 26 20 [0-1f] 20 26 20 22 3b 22 20 26 20 [0-1f] 2c 20 22 [0-1f] 22 2c 20 22 65 22 29 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}