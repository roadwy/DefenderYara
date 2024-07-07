
rule TrojanDownloader_O97M_EncDoc_STWV_MTB{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.STWV!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {22 44 35 2d 44 37 30 41 2d 34 33 38 42 2d 38 41 34 32 2d 39 38 34 22 } //1 "D5-D70A-438B-8A42-984"
		$a_01_1 = {52 65 70 6c 61 63 65 28 22 5c 4a 35 6f 6b 6c 7a 6d 35 70 70 44 4a 35 6f 6b 6c 7a 6d 35 74 4a 35 6f 6b 6c 7a 6d 35 5c 52 6f 4a 35 6f 6b 6c 7a 6d 35 6d 69 6e 67 5c 62 65 6c 6c 61 2e 6c 6e 6b 22 2c 20 22 4a 35 6f 6b 6c 7a 6d 35 22 2c 20 22 61 22 29 } //1 Replace("\J5oklzm5ppDJ5oklzm5tJ5oklzm5\RoJ5oklzm5ming\bella.lnk", "J5oklzm5", "a")
		$a_01_2 = {22 43 3a 5c 5c 55 73 65 72 73 5c 5c 50 75 62 6c 69 63 5c 5c 77 65 62 73 65 72 76 69 63 65 73 2e 65 5e 78 65 22 } //1 "C:\\Users\\Public\\webservices.e^xe"
		$a_03_3 = {67 6f 64 6b 6e 6f 77 73 20 3d 20 52 65 70 6c 61 63 65 28 22 63 6d 64 2e 90 02 2f 20 2f 63 20 70 6f 77 5e 90 02 1f 5e 90 02 1f 2f 57 20 30 31 20 63 5e 75 5e 72 6c 20 68 74 74 5e 70 3a 2f 2f 31 37 32 2e 39 33 2e 32 31 33 2e 31 34 39 3a 38 30 38 30 2f 75 70 6c 6f 61 64 2f 90 02 2f 2e 90 02 1f 5e 90 02 1f 20 2d 6f 20 22 20 26 20 76 61 7a 77 20 26 20 22 3b 22 20 26 20 76 61 7a 77 2c 20 22 90 02 1f 22 2c 20 22 65 22 29 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1) >=4
 
}