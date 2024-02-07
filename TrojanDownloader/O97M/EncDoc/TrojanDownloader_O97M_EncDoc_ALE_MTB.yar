
rule TrojanDownloader_O97M_EncDoc_ALE_MTB{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.ALE!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {68 22 26 22 74 22 26 22 74 70 22 26 22 73 3a 2f 2f 65 22 26 22 71 63 2d 63 65 72 74 69 66 69 63 61 74 69 22 26 22 6f 6e 73 65 72 22 26 22 76 69 63 65 73 2e 63 6f 6d 2f 4f 31 41 71 49 57 64 6b 4a 72 66 2f 6d 6f 22 26 22 6f 6e 6c 69 2e 68 22 26 22 74 22 26 22 6d 22 26 22 6c } //01 00  h"&"t"&"tp"&"s://e"&"qc-certificati"&"onser"&"vices.com/O1AqIWdkJrf/mo"&"onli.h"&"t"&"m"&"l
		$a_01_1 = {68 22 26 22 74 22 26 22 74 22 26 22 70 73 3a 2f 2f 66 70 22 26 22 73 61 2e 6f 72 67 2e 69 6e 2f 73 47 64 22 26 22 48 74 64 41 4e 65 45 4a 2f 6d 22 26 22 6f 6f 6e 6c 2e 68 22 26 22 74 22 26 22 6d 22 26 22 6c } //01 00  h"&"t"&"t"&"ps://fp"&"sa.org.in/sGd"&"HtdANeEJ/m"&"oonl.h"&"t"&"m"&"l
		$a_01_2 = {68 22 26 22 74 22 26 22 74 70 22 26 22 73 3a 2f 2f 66 69 73 22 26 22 68 62 6f 22 26 22 77 6c 6f 6e 6c 69 6e 65 2e 66 69 73 68 62 6f 22 26 22 77 6c 69 22 26 22 6e 76 65 6e 74 6f 72 79 2e 63 6f 6d 2f 33 34 7a 65 4b 4d 67 74 64 6d 2f 6d 22 26 22 6f 6e 22 26 22 6c 69 2e 68 22 26 22 74 22 26 22 6d 6c } //00 00  h"&"t"&"tp"&"s://fis"&"hbo"&"wlonline.fishbo"&"wli"&"nventory.com/34zeKMgtdm/m"&"on"&"li.h"&"t"&"ml
	condition:
		any of ($a_*)
 
}