
rule TrojanDownloader_O97M_EncDoc_QBR_MTB{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.QBR!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 03 00 00 "
		
	strings :
		$a_01_0 = {68 22 26 22 74 22 26 22 74 22 26 22 70 73 3a 2f 2f 6d 61 78 64 69 67 69 74 69 7a 69 6e 67 2e 63 6f 6d 2f 77 41 62 43 4e 4d 55 6d 2f 70 70 2e 68 22 26 22 74 22 26 22 6d 6c 22 } //1 h"&"t"&"t"&"ps://maxdigitizing.com/wAbCNMUm/pp.h"&"t"&"ml"
		$a_01_1 = {68 22 26 22 74 22 26 22 74 22 26 22 70 73 3a 2f 2f 74 75 72 6e 69 70 73 68 6f 70 2e 63 6f 6d 2f 69 68 69 52 7a 6f 69 31 2f 70 70 2e 68 22 26 22 74 6d 6c 22 } //1 h"&"t"&"t"&"ps://turnipshop.com/ihiRzoi1/pp.h"&"tml"
		$a_01_2 = {68 22 26 22 74 22 26 22 74 70 73 3a 2f 2f 64 79 6e 61 6d 69 63 6c 69 66 74 73 2e 63 6f 2e 69 6e 2f 31 50 57 51 51 63 76 30 44 2f 70 70 2e 68 22 26 22 74 6d 6c 20 22 } //1 h"&"t"&"tps://dynamiclifts.co.in/1PWQQcv0D/pp.h"&"tml "
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=1
 
}