
rule TrojanDownloader_O97M_Valyria_I{
	meta:
		description = "TrojanDownloader:O97M/Valyria.I,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {50 72 69 76 61 74 65 20 44 65 63 6c 61 72 65 20 50 74 72 53 61 66 65 20 46 75 6e 63 74 69 6f 6e 20 [0-10] 20 4c 69 62 20 22 73 68 65 6c 6c 33 32 22 20 41 6c 69 61 73 20 22 53 68 65 6c 6c 45 78 65 63 75 74 65 41 22 } //1
		$a_03_1 = {28 4d 69 64 28 [0-10] 2c 20 28 31 20 2a 20 33 20 2d 20 32 29 2c 20 4c 65 6e 28 [0-10] 29 20 2d 20 28 37 20 2a 20 31 20 2d 20 35 29 29 29 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}