
rule TrojanDownloader_O97M_EncDoc_QBT_MTB{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.QBT!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 03 00 00 "
		
	strings :
		$a_01_0 = {68 22 26 22 74 22 26 22 74 22 26 22 70 73 3a 2f 2f 64 68 61 72 6d 61 73 61 73 74 68 61 74 72 75 73 74 2e 63 6f 6d 2f 63 45 4a 59 63 53 74 71 6c 41 66 2f 68 72 2e 68 22 26 22 74 6d 6c } //1 h"&"t"&"t"&"ps://dharmasasthatrust.com/cEJYcStqlAf/hr.h"&"tml
		$a_01_1 = {68 22 26 22 74 22 26 22 74 22 26 22 70 73 3a 2f 2f 73 68 61 6c 73 61 33 64 2e 63 6f 6d 2f 55 47 71 57 4e 43 4c 54 2f 68 72 2e 68 22 26 22 74 22 26 22 6d 6c } //1 h"&"t"&"t"&"ps://shalsa3d.com/UGqWNCLT/hr.h"&"t"&"ml
		$a_01_2 = {68 22 26 22 74 22 26 22 74 22 26 22 70 73 3a 2f 2f 68 61 72 6f 6c 64 68 61 6c 6c 72 6f 6f 66 69 6e 67 2e 6e 65 74 2f 70 41 7a 38 4f 36 33 47 6e 2f 68 72 2e 68 22 26 22 74 6d 6c } //1 h"&"t"&"t"&"ps://haroldhallroofing.net/pAz8O63Gn/hr.h"&"tml
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=1
 
}