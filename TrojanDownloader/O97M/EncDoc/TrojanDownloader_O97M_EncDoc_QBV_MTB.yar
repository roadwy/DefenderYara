
rule TrojanDownloader_O97M_EncDoc_QBV_MTB{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.QBV!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 03 00 00 "
		
	strings :
		$a_01_0 = {68 22 26 22 74 74 70 22 26 22 73 3a 2f 2f 67 69 6c 6c 63 61 72 74 2e 63 6f 6d 2f 43 64 70 6d 6f 79 68 72 2f 6b 65 79 2e 78 22 26 22 6d 22 26 22 6c } //1 h"&"ttp"&"s://gillcart.com/Cdpmoyhr/key.x"&"m"&"l
		$a_01_1 = {68 22 26 22 74 22 26 22 74 70 22 26 22 73 3a 2f 2f 67 65 69 74 2e 69 6e 2f 4d 65 4f 6c 45 39 58 78 64 2f 6b 65 79 2e 78 22 26 22 6d 22 26 22 6c } //1 h"&"t"&"tp"&"s://geit.in/MeOlE9Xxd/key.x"&"m"&"l
		$a_01_2 = {68 22 26 22 74 74 22 26 22 70 73 3a 2f 2f 6d 65 72 63 61 6e 65 74 73 2e 63 6f 6d 2f 39 44 50 5a 71 41 66 5a 64 71 35 7a 2f 6b 65 79 2e 78 22 26 22 6d 22 26 22 6c } //1 h"&"tt"&"ps://mercanets.com/9DPZqAfZdq5z/key.x"&"m"&"l
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=1
 
}