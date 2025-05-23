
rule TrojanDownloader_O97M_Emotet_EHPK_MTB{
	meta:
		description = "TrojanDownloader:O97M/Emotet.EHPK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {74 22 26 22 74 22 26 22 70 3a 2f 2f 6d 22 26 22 70 6d 22 26 22 68 69 22 26 22 6e 6f 2e 63 22 26 22 6f 22 26 22 6d 2f 6d 22 26 22 6f 64 22 26 22 75 6c 22 26 22 65 73 2f 7a 22 26 22 44 67 22 26 22 32 22 26 22 49 35 30 22 26 22 55 56 22 26 22 53 6a 22 26 22 6f 6d 22 26 22 37 32 22 26 22 59 72 22 26 22 75 35 22 26 22 76 2f } //1 t"&"t"&"p://m"&"pm"&"hi"&"no.c"&"o"&"m/m"&"od"&"ul"&"es/z"&"Dg"&"2"&"I50"&"UV"&"Sj"&"om"&"72"&"Yr"&"u5"&"v/
		$a_01_1 = {74 22 26 22 74 70 22 26 22 3a 2f 2f 6d 22 26 22 6f 73 22 26 22 62 69 22 26 22 72 65 22 26 22 73 6f 22 26 22 75 72 22 26 22 63 65 22 26 22 73 2e 63 22 26 22 6f 22 26 22 6d 2f 63 22 26 22 67 22 26 22 69 2d 62 22 26 22 69 6e 2f 62 22 26 22 54 75 22 26 22 70 77 22 26 22 33 38 22 26 22 52 5a 22 26 22 48 78 22 26 22 58 4b 22 26 22 32 57 22 26 22 65 62 22 26 22 34 31 2f } //1 t"&"tp"&"://m"&"os"&"bi"&"re"&"so"&"ur"&"ce"&"s.c"&"o"&"m/c"&"g"&"i-b"&"in/b"&"Tu"&"pw"&"38"&"RZ"&"Hx"&"XK"&"2W"&"eb"&"41/
		$a_01_2 = {74 22 26 22 74 70 22 26 22 73 3a 2f 2f 77 22 26 22 77 22 26 22 77 2e 6d 22 26 22 61 73 74 22 26 22 65 6c 22 26 22 65 63 22 26 22 6f 6d 2e 63 22 26 22 6c 2f 71 37 22 26 22 63 6a 22 26 22 76 36 22 26 22 6c 47 22 26 22 4f 53 2f 6f 22 26 22 2f } //1 t"&"tp"&"s://w"&"w"&"w.m"&"ast"&"el"&"ec"&"om.c"&"l/q7"&"cj"&"v6"&"lG"&"OS/o"&"/
		$a_01_3 = {74 22 26 22 74 70 22 26 22 3a 2f 2f 6d 22 26 22 6f 79 22 26 22 6e 61 22 26 22 6e 2e 63 22 26 22 6f 22 26 22 6d 2f 73 22 26 22 65 78 22 26 22 6d 61 22 26 22 74 74 22 26 22 65 72 22 26 22 73 2e 65 22 26 22 75 2f 6d 22 26 22 51 62 22 26 22 74 59 22 26 22 47 47 2f } //1 t"&"tp"&"://m"&"oy"&"na"&"n.c"&"o"&"m/s"&"ex"&"ma"&"tt"&"er"&"s.e"&"u/m"&"Qb"&"tY"&"GG/
		$a_01_4 = {74 22 26 22 74 22 26 22 70 3a 2f 2f 77 22 26 22 77 22 26 22 77 2e 6c 22 26 22 61 6b 22 26 22 6f 72 2e 63 22 26 22 68 2f 6c 61 22 26 22 6b 6f 22 26 22 72 2f 75 22 26 22 34 31 74 22 26 22 61 69 22 26 22 6d 50 2f } //1 t"&"t"&"p://w"&"w"&"w.l"&"ak"&"or.c"&"h/la"&"ko"&"r/u"&"41t"&"ai"&"mP/
		$a_01_5 = {74 22 26 22 74 70 3a 2f 2f 77 22 26 22 77 22 26 22 77 2e 6d 22 26 22 65 74 22 26 22 61 6c 22 26 22 67 61 22 26 22 73 2e 63 22 26 22 6f 22 26 22 6d 2e 61 22 26 22 72 2f 77 22 26 22 70 2d 69 6e 22 26 22 63 6c 75 22 26 22 64 65 22 26 22 73 2f 32 45 22 26 22 63 6f 22 26 22 62 67 2f } //1 t"&"tp://w"&"w"&"w.m"&"et"&"al"&"ga"&"s.c"&"o"&"m.a"&"r/w"&"p-in"&"clu"&"de"&"s/2E"&"co"&"bg/
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}