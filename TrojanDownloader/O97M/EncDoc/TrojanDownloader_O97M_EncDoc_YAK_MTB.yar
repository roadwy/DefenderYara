
rule TrojanDownloader_O97M_EncDoc_YAK_MTB{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.YAK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 06 00 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 3a 2f 2f 31 38 35 2e 31 38 33 2e 39 38 2e 31 34 2f 66 6f 6e 74 73 75 70 64 61 74 65 2e 70 68 70 } //1 http://185.183.98.14/fontsupdate.php
		$a_01_1 = {68 74 74 70 3a 2f 2f 70 61 64 67 65 74 74 63 6f 6e 73 75 6c 74 61 6e 74 73 2e 63 61 2f 74 61 75 2e 67 69 66 } //1 http://padgettconsultants.ca/tau.gif
		$a_01_2 = {68 74 74 70 3a 2f 2f 77 77 77 2e 62 75 73 6e 75 61 6e 73 61 2e 6d 79 2e 69 64 2f 70 62 6f 6f 6a 66 7a 64 7a 70 75 62 2f 38 38 38 38 38 38 38 2e 70 6e 67 } //1 http://www.busnuansa.my.id/pboojfzdzpub/8888888.png
		$a_01_3 = {68 74 74 70 3a 2f 2f 67 69 64 73 74 61 78 69 2e 6e 6c 2f 6d 72 73 7a 68 65 75 68 65 2f 38 38 38 38 38 38 38 2e 70 6e 67 } //1 http://gidstaxi.nl/mrszheuhe/8888888.png
		$a_00_4 = {43 3a 5c 50 65 72 66 4c 6f 67 65 73 74 5c 53 63 68 72 6f 74 5c 65 78 70 6c 6f 72 65 72 73 } //1 C:\PerfLogest\Schrot\explorers
		$a_00_5 = {43 3a 5c 50 72 6f 67 72 61 6d 64 61 74 61 5c 47 6f 6c 61 73 44 68 } //1 C:\Programdata\GolasDh
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=2
 
}