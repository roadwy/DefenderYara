
rule TrojanDownloader_O97M_Gozi_PAAA_MTB{
	meta:
		description = "TrojanDownloader:O97M/Gozi.PAAA!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {76 62 5f 6e 61 6d 65 3d 22 66 6f 67 6c 69 6f 31 22 } //1 vb_name="foglio1"
		$a_03_1 = {66 6f 72 65 61 63 68 64 61 69 6e 62 6f 6c 65 65 61 6e 63 3d 28 62 6e 28 22 3d 22 26 64 61 2c 31 2b 37 29 29 3a [0-3f] 28 28 [0-3f] 5f 70 61 67 6f 29 29 6e 65 78 74 77 } //1
		$a_01_2 = {28 28 28 28 28 28 28 28 28 28 72 75 6e 28 28 28 28 28 28 28 28 28 28 22 6d 22 26 22 34 22 26 22 22 29 } //1 ((((((((((run(((((((((("m"&"4"&"")
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}