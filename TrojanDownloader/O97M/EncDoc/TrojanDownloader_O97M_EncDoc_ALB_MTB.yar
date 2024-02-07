
rule TrojanDownloader_O97M_EncDoc_ALB_MTB{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.ALB!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {68 22 26 22 74 22 26 22 74 22 26 22 70 3a 2f 2f 70 22 26 22 72 6f 66 6c 69 7a 62 6f 77 6c 65 73 2e 63 6f 6d 2f 46 43 32 38 79 6b 34 53 78 37 52 72 2f 73 22 26 22 65 70 2e 68 22 26 22 74 6d 6c } //01 00  h"&"t"&"t"&"p://p"&"roflizbowles.com/FC28yk4Sx7Rr/s"&"ep.h"&"tml
		$a_01_1 = {68 22 26 22 74 22 26 22 74 22 26 22 70 3a 2f 2f 61 22 26 22 63 63 65 73 73 2d 63 73 2e 63 6f 6d 2f 57 48 30 64 4f 75 46 33 31 56 6a 6f 2f 73 65 70 2e 68 22 26 22 74 6d 6c } //01 00  h"&"t"&"t"&"p://a"&"ccess-cs.com/WH0dOuF31Vjo/sep.h"&"tml
		$a_01_2 = {68 22 26 22 74 22 26 22 74 22 26 22 70 22 26 22 73 3a 2f 2f 64 22 26 22 72 22 26 22 65 61 6d 6f 6e 76 69 62 65 73 2e 67 72 2f 50 48 35 4e 6d 4b 6a 68 59 37 6a 73 2f 73 65 70 2e 68 22 26 22 74 22 26 22 6d 6c } //00 00  h"&"t"&"t"&"p"&"s://d"&"r"&"eamonvibes.gr/PH5NmKjhY7js/sep.h"&"t"&"ml
	condition:
		any of ($a_*)
 
}