
rule TrojanDownloader_O97M_Emotet_ALS_MTB{
	meta:
		description = "TrojanDownloader:O97M/Emotet.ALS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 03 00 00 "
		
	strings :
		$a_01_0 = {67 6e 69 66 2e 6f 72 67 2f 61 64 6d 69 6e 69 73 74 72 61 74 6f 72 2f 47 36 38 48 77 55 47 6c 4b 4e 4a 4e 55 32 76 68 35 63 7a 2f } //1 gnif.org/administrator/G68HwUGlKNJNU2vh5cz/
		$a_01_1 = {65 64 6f 72 61 73 65 67 75 72 6f 73 2e 63 6f 6d 2e 62 72 2f 63 67 69 2d 62 69 6e 2f 6c 37 5a 45 52 76 35 64 65 4e 73 66 7a 6c 5a 55 5a 2f } //1 edoraseguros.com.br/cgi-bin/l7ZERv5deNsfzlZUZ/
		$a_01_2 = {73 61 6e 6f 6d 61 2e 61 6c 6c 72 65 6e 74 2e 6e 6c 2f 63 67 69 2d 62 69 6e 2f 4b 58 62 49 35 4f 68 4c 4a 2f } //1 sanoma.allrent.nl/cgi-bin/KXbI5OhLJ/
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=1
 
}