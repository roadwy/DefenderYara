
rule TrojanDownloader_O97M_Emotet_PDA_MTB{
	meta:
		description = "TrojanDownloader:O97M/Emotet.PDA!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 05 00 00 "
		
	strings :
		$a_01_0 = {22 68 22 26 22 74 74 70 22 26 22 73 3a 2f 2f 63 61 22 26 22 6e 6f 22 26 22 70 75 22 26 22 73 65 22 26 22 6e 67 2e 69 22 26 22 6e 2f 62 2f 35 22 26 22 47 31 22 26 22 73 6c 22 26 22 36 78 2f 22 2c } //1 "h"&"ttp"&"s://ca"&"no"&"pu"&"se"&"ng.i"&"n/b/5"&"G1"&"sl"&"6x/",
		$a_01_1 = {22 68 22 26 22 74 74 70 22 26 22 3a 2f 2f 73 65 22 26 22 73 63 22 26 22 6f 2d 6b 22 26 22 73 2e 63 22 26 22 6f 22 26 22 6d 2f 77 22 26 22 70 2d 63 22 26 22 6f 6e 22 26 22 74 65 22 26 22 6e 74 2f 72 22 26 22 44 41 22 26 22 52 41 22 26 22 43 79 22 26 22 46 31 22 26 22 6c 44 22 26 22 4f 7a 22 26 22 39 47 22 26 22 50 31 22 26 22 72 2f 22 2c } //1 "h"&"ttp"&"://se"&"sc"&"o-k"&"s.c"&"o"&"m/w"&"p-c"&"on"&"te"&"nt/r"&"DA"&"RA"&"Cy"&"F1"&"lD"&"Oz"&"9G"&"P1"&"r/",
		$a_01_2 = {22 68 22 26 22 74 74 22 26 22 70 3a 2f 2f 64 22 26 22 65 22 26 22 76 2e 6c 65 22 26 22 61 72 22 26 22 6e 63 22 26 22 61 72 22 26 22 61 75 22 26 22 64 69 22 26 22 6f 2e 63 22 26 22 6f 22 26 22 6d 2f 77 22 26 22 70 2d 61 22 26 22 64 6d 22 26 22 69 22 26 22 6e 2f 76 36 22 26 22 49 4b 22 26 22 49 44 22 26 22 75 39 22 26 22 30 22 26 22 6b 38 22 26 22 43 36 22 26 22 59 38 2f 22 2c } //1 "h"&"tt"&"p://d"&"e"&"v.le"&"ar"&"nc"&"ar"&"au"&"di"&"o.c"&"o"&"m/w"&"p-a"&"dm"&"i"&"n/v6"&"IK"&"ID"&"u9"&"0"&"k8"&"C6"&"Y8/",
		$a_01_3 = {22 68 22 26 22 74 74 22 26 22 70 3a 2f 2f 66 22 26 22 61 73 22 26 22 74 78 22 26 22 6d 66 22 26 22 67 2e 63 22 26 22 6f 22 26 22 6d 2f 76 6f 22 26 22 6c 75 22 26 22 70 74 22 26 22 61 74 22 26 22 75 22 26 22 6d 2d 76 6f 22 26 22 6c 75 22 26 22 70 74 22 26 22 61 74 22 26 22 75 6d 2f 72 22 26 22 68 32 22 26 22 43 4e 22 26 22 4d 48 22 26 22 4e 6a 22 26 22 64 67 22 26 22 62 36 2f 22 2c } //1 "h"&"tt"&"p://f"&"as"&"tx"&"mf"&"g.c"&"o"&"m/vo"&"lu"&"pt"&"at"&"u"&"m-vo"&"lu"&"pt"&"at"&"um/r"&"h2"&"CN"&"MH"&"Nj"&"dg"&"b6/",
		$a_01_4 = {22 68 22 26 22 74 74 22 26 22 70 3a 2f 2f 73 22 26 22 65 22 26 22 70 2e 64 66 22 26 22 77 73 22 26 22 6f 6c 22 26 22 61 72 2e 63 22 26 22 6c 75 22 26 22 62 2f 68 22 26 22 7a 68 22 26 22 33 76 2f 63 30 22 26 22 38 33 22 26 22 75 6a 22 26 22 4f 35 22 26 22 62 31 22 26 22 31 74 22 26 22 75 6f 22 26 22 39 32 2f 22 2c } //1 "h"&"tt"&"p://s"&"e"&"p.df"&"ws"&"ol"&"ar.c"&"lu"&"b/h"&"zh"&"3v/c0"&"83"&"uj"&"O5"&"b1"&"1t"&"uo"&"92/",
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=1
 
}