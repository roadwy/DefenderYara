
rule TrojanDownloader_O97M_EncDoc_EJPK_MTB{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.EJPK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 05 00 00 "
		
	strings :
		$a_01_0 = {3a 2f 22 26 22 2f 70 22 26 22 72 22 26 22 61 22 26 22 61 22 26 22 63 22 26 22 68 69 22 26 22 63 22 26 22 68 22 26 22 65 22 26 22 6d 22 26 22 66 6f 22 26 22 6f 64 2e 63 22 26 22 6f 22 26 22 6d 2f 77 22 26 22 70 2d 63 22 26 22 6f 22 26 22 6e 74 22 26 22 65 6e 22 26 22 74 2f 4d 22 26 22 77 6d 22 26 22 6f 73 2f } //1 :/"&"/p"&"r"&"a"&"a"&"c"&"hi"&"c"&"h"&"e"&"m"&"fo"&"od.c"&"o"&"m/w"&"p-c"&"o"&"nt"&"en"&"t/M"&"wm"&"os/
		$a_01_1 = {3a 2f 2f 62 22 26 22 6f 22 26 22 73 22 26 22 6e 22 26 22 79 2e 63 22 26 22 6f 22 26 22 6d 2f 61 22 26 22 73 70 22 26 22 6e 65 22 26 22 74 5f 63 22 26 22 6c 22 26 22 69 22 26 22 65 22 26 22 6e 22 26 22 74 2f 72 22 26 22 6e 22 26 22 4d 22 26 22 70 22 26 22 30 22 26 22 6f 22 26 22 66 22 26 22 52 2f } //1 ://b"&"o"&"s"&"n"&"y.c"&"o"&"m/a"&"sp"&"ne"&"t_c"&"l"&"i"&"e"&"n"&"t/r"&"n"&"M"&"p"&"0"&"o"&"f"&"R/
		$a_01_2 = {3a 2f 2f 62 22 26 22 6f 72 22 26 22 67 65 22 26 22 6c 69 22 26 22 6e 2e 6f 22 26 22 72 22 26 22 67 2f 62 22 26 22 65 6c 22 26 22 7a 65 22 26 22 62 75 22 26 22 62 2f 6f 22 26 22 6b 77 22 26 22 52 57 22 26 22 7a 31 22 26 22 43 2f } //1 ://b"&"or"&"ge"&"li"&"n.o"&"r"&"g/b"&"el"&"ze"&"bu"&"b/o"&"kw"&"RW"&"z1"&"C/
		$a_01_3 = {3a 22 26 22 2f 2f 6c 6f 22 26 22 70 65 22 26 22 73 70 22 26 22 75 62 22 26 22 6c 69 22 26 22 63 69 22 26 22 64 61 22 26 22 64 65 2e 63 22 26 22 6f 22 26 22 6d 2f 63 67 69 2d 62 69 6e 2f 65 22 26 22 35 52 22 26 22 35 6f 22 26 22 47 34 22 26 22 69 45 61 22 26 22 51 6e 22 26 22 78 51 22 26 22 72 5a 22 26 22 44 68 2f } //1 :"&"//lo"&"pe"&"sp"&"ub"&"li"&"ci"&"da"&"de.c"&"o"&"m/cgi-bin/e"&"5R"&"5o"&"G4"&"iEa"&"Qn"&"xQ"&"rZ"&"Dh/
		$a_01_4 = {3a 2f 2f 6c 22 26 22 6f 22 26 22 61 2d 68 22 26 22 6b 2e 63 22 26 22 6f 22 26 22 6d 2f 77 22 26 22 70 2d 63 6f 22 26 22 6e 22 26 22 74 65 22 26 22 6e 74 2f 66 66 22 26 22 42 61 22 26 22 67 2f } //1 ://l"&"o"&"a-h"&"k.c"&"o"&"m/w"&"p-co"&"n"&"te"&"nt/ff"&"Ba"&"g/
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=1
 
}