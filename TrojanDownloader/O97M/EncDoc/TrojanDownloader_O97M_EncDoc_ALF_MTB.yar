
rule TrojanDownloader_O97M_EncDoc_ALF_MTB{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.ALF!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 03 00 00 "
		
	strings :
		$a_01_0 = {68 22 26 22 74 22 26 22 74 70 22 26 22 73 3a 2f 2f 73 61 22 26 22 6d 74 6e 70 79 2e 6f 72 67 2f 62 76 65 43 47 4b 54 58 2f 67 68 62 2e 68 22 26 22 74 22 26 22 6d 22 26 22 6c } //1 h"&"t"&"tp"&"s://sa"&"mtnpy.org/bveCGKTX/ghb.h"&"t"&"m"&"l
		$a_01_1 = {68 22 26 22 74 74 22 26 22 70 73 3a 2f 2f 6d 22 26 22 61 73 73 22 26 22 6e 67 6f 2e 6f 72 67 2f 64 58 4b 76 79 4b 56 39 76 38 63 2f 67 68 62 2e 68 22 26 22 74 22 26 22 6d 22 26 22 6c } //1 h"&"tt"&"ps://m"&"ass"&"ngo.org/dXKvyKV9v8c/ghb.h"&"t"&"m"&"l
		$a_01_2 = {68 22 26 22 74 22 26 22 74 70 73 3a 2f 2f 76 61 22 26 22 74 68 22 26 22 69 72 69 79 61 72 2e 6f 72 67 2f 75 79 30 54 6b 30 6b 65 4a 55 72 2f 67 68 62 2e 68 22 26 22 74 22 26 22 6d 22 26 22 6c } //1 h"&"t"&"tps://va"&"th"&"iriyar.org/uy0Tk0keJUr/ghb.h"&"t"&"m"&"l
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=1
 
}