
rule TrojanDownloader_O97M_Gozi_YA_MTB{
	meta:
		description = "TrojanDownloader:O97M/Gozi.YA!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 06 00 00 "
		
	strings :
		$a_00_0 = {53 75 62 20 61 75 74 6f 6f 70 65 6e 28 29 } //1 Sub autoopen()
		$a_00_1 = {43 61 6c 6c 20 55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 } //1 Call URLDownloadToFile
		$a_00_2 = {68 74 74 70 3a 2f 2f 39 62 67 6e 71 2e 63 6f 6d 2f 69 7a 35 2f 79 61 63 61 2e 70 68 70 } //1 http://9bgnq.com/iz5/yaca.php
		$a_00_3 = {68 74 74 70 3a 2f 2f 64 37 75 61 70 2e 63 6f 6d 2f 69 7a 35 2f 79 61 63 61 2e 70 68 70 3f 6c 3d 68 74 74 70 3a 2f 2f 74 7a 65 31 2e 63 61 62 } //1 http://d7uap.com/iz5/yaca.php?l=http://tze1.cab
		$a_00_4 = {68 74 74 70 3a 2f 2f 70 37 68 6e 65 2e 63 6f 6d 2f 69 7a 35 2f 79 61 63 61 2e 70 68 70 3f 6c 3d 74 7a 65 33 2e 63 61 62 22 2c 20 4a 4b } //1 http://p7hne.com/iz5/yaca.php?l=tze3.cab", JK
		$a_00_5 = {43 2e 74 6d 70 } //1 C.tmp
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=4
 
}