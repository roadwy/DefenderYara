
rule TrojanDownloader_O97M_Emotet_YPD_MTB{
	meta:
		description = "TrojanDownloader:O97M/Emotet.YPD!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 06 00 00 "
		
	strings :
		$a_01_0 = {3a 2f 22 26 22 2f 68 22 26 22 6f 73 22 26 22 74 22 26 22 61 6c 2d 61 6c 66 22 26 22 6f 6e 22 26 22 73 22 26 22 6f 31 22 26 22 32 2e 63 22 26 22 6f 6d 2f 63 22 26 22 6c 61 22 26 22 73 22 26 22 65 73 2f 53 22 26 22 4b 74 22 26 22 50 76 22 26 22 76 2f } //1 :/"&"/h"&"os"&"t"&"al-alf"&"on"&"s"&"o1"&"2.c"&"om/c"&"la"&"s"&"es/S"&"Kt"&"Pv"&"v/
		$a_01_1 = {3a 2f 22 26 22 2f 68 6f 22 26 22 77 65 22 26 22 73 69 22 26 22 74 67 22 26 22 6f 69 22 26 22 6e 22 26 22 67 2e 63 22 26 22 6f 6d 2f 69 22 26 22 6d 61 22 26 22 67 65 22 26 22 73 2f 48 22 26 22 79 61 22 26 22 44 6e 22 26 22 6c 62 22 26 22 6c 36 22 26 22 4b 37 22 26 22 74 62 22 26 22 68 32 22 26 22 4c 75 22 26 22 67 79 22 26 22 73 2f } //1 :/"&"/ho"&"we"&"si"&"tg"&"oi"&"n"&"g.c"&"om/i"&"ma"&"ge"&"s/H"&"ya"&"Dn"&"lb"&"l6"&"K7"&"tb"&"h2"&"Lu"&"gy"&"s/
		$a_01_2 = {3a 2f 22 26 22 2f 77 77 22 26 22 77 2e 6a 64 22 26 22 73 65 22 26 22 72 72 22 26 22 61 6c 68 22 26 22 65 22 26 22 72 69 22 26 22 61 2e 63 22 26 22 6f 22 26 22 6d 2e 62 22 26 22 72 2f 63 22 26 22 67 22 26 22 69 2d 62 22 26 22 69 6e 2f 4b 22 26 22 46 22 26 22 47 22 26 22 36 2f } //1 :/"&"/ww"&"w.jd"&"se"&"rr"&"alh"&"e"&"ri"&"a.c"&"o"&"m.b"&"r/c"&"g"&"i-b"&"in/K"&"F"&"G"&"6/
		$a_01_3 = {3a 2f 2f 69 6e 22 26 22 74 22 26 22 65 69 22 26 22 72 61 22 26 22 64 6f 2e 63 22 26 22 6f 22 26 22 6d 2e 62 22 26 22 72 2f 66 22 26 22 6f 6e 22 26 22 74 73 2f 37 22 26 22 64 4a 22 26 22 43 56 22 26 22 76 75 22 26 22 45 35 22 26 22 78 33 22 26 22 59 72 22 26 22 47 51 22 26 22 73 32 22 26 22 6f 4a 22 26 22 7a 2f } //1 ://in"&"t"&"ei"&"ra"&"do.c"&"o"&"m.b"&"r/f"&"on"&"ts/7"&"dJ"&"CV"&"vu"&"E5"&"x3"&"Yr"&"GQ"&"s2"&"oJ"&"z/
		$a_01_4 = {3a 2f 22 26 22 2f 69 63 22 26 22 69 65 22 26 22 65 2e 75 6e 22 26 22 74 69 22 26 22 72 74 22 26 22 61 2e 61 22 26 22 63 2e 69 22 26 22 64 2f 74 22 26 22 65 73 22 26 22 74 2f 47 22 26 22 63 63 22 26 22 52 22 26 22 77 2f } //1 :/"&"/ic"&"ie"&"e.un"&"ti"&"rt"&"a.a"&"c.i"&"d/t"&"es"&"t/G"&"cc"&"R"&"w/
		$a_01_5 = {3a 2f 22 26 22 2f 69 64 22 26 22 65 22 26 22 6f 73 22 26 22 6f 2e 63 22 26 22 6f 22 26 22 6d 2e 74 22 26 22 77 2f 63 22 26 22 67 22 26 22 69 2d 62 22 26 22 69 22 26 22 6e 2f 7a 4c 22 26 22 72 6e 22 26 22 42 64 22 26 22 32 45 22 26 22 67 31 22 26 22 4e 33 22 26 22 55 56 22 26 22 79 35 22 26 22 79 4c 2f } //1 :/"&"/id"&"e"&"os"&"o.c"&"o"&"m.t"&"w/c"&"g"&"i-b"&"i"&"n/zL"&"rn"&"Bd"&"2E"&"g1"&"N3"&"UV"&"y5"&"yL/
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=1
 
}