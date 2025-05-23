
rule TrojanDownloader_O97M_Emotet_SPD_MTB{
	meta:
		description = "TrojanDownloader:O97M/Emotet.SPD!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 06 00 00 "
		
	strings :
		$a_01_0 = {3a 2f 22 26 22 2f 77 22 26 22 77 22 26 22 77 2e 65 22 26 22 6c 6f 22 26 22 67 2e 68 22 26 22 72 2f 69 50 22 26 22 70 35 22 26 22 46 55 22 26 22 37 65 22 26 22 54 52 22 26 22 57 6b 22 26 22 55 78 22 26 22 58 6f 22 26 22 69 4f 22 26 22 70 2f 35 22 26 22 75 55 22 26 22 35 52 22 26 22 4b 2f } //1 :/"&"/w"&"w"&"w.e"&"lo"&"g.h"&"r/iP"&"p5"&"FU"&"7e"&"TR"&"Wk"&"Ux"&"Xo"&"iO"&"p/5"&"uU"&"5R"&"K/
		$a_01_1 = {3a 2f 22 26 22 2f 77 77 22 26 22 77 2e 66 22 26 22 6c 61 22 26 22 73 68 2d 69 22 26 22 6e 22 26 22 63 2e 63 22 26 22 6f 22 26 22 6d 2f 67 22 26 22 72 6f 22 26 22 75 70 2f 69 22 26 22 67 69 22 26 22 72 6c 2f 63 22 26 22 73 22 26 22 73 2f 51 22 26 22 43 44 22 26 22 61 39 22 26 22 46 67 22 26 22 58 77 22 26 22 77 6b 22 26 22 79 77 22 26 22 6e 47 22 26 22 5a 67 22 26 22 42 68 2f } //1 :/"&"/ww"&"w.f"&"la"&"sh-i"&"n"&"c.c"&"o"&"m/g"&"ro"&"up/i"&"gi"&"rl/c"&"s"&"s/Q"&"CD"&"a9"&"Fg"&"Xw"&"wk"&"yw"&"nG"&"Zg"&"Bh/
		$a_01_2 = {3a 2f 22 26 22 2f 67 6f 22 26 22 6f 67 22 26 22 6c 65 22 26 22 66 61 22 26 22 63 69 22 26 22 6c 2e 63 22 26 22 6f 22 26 22 6d 2e 62 22 26 22 72 2f 62 22 26 22 6c 61 22 26 22 63 6b 22 26 22 62 6f 22 26 22 78 2f 43 22 26 22 71 53 22 26 22 78 34 22 26 22 73 56 22 26 22 58 70 22 26 22 35 45 22 26 22 67 2f } //1 :/"&"/go"&"og"&"le"&"fa"&"ci"&"l.c"&"o"&"m.b"&"r/b"&"la"&"ck"&"bo"&"x/C"&"qS"&"x4"&"sV"&"Xp"&"5E"&"g/
		$a_01_3 = {3a 2f 22 26 22 2f 77 22 26 22 77 22 26 22 77 2e 65 22 26 22 6e 22 26 22 73 2d 73 22 26 22 65 74 22 26 22 69 66 2e 64 22 26 22 7a 2f 61 22 26 22 6e 6e 22 26 22 75 61 22 26 22 69 72 22 26 22 65 2f 59 22 26 22 75 38 22 26 22 77 6a 22 26 22 48 4c 22 26 22 6d 41 22 26 22 7a 71 22 26 22 79 55 22 26 22 53 33 22 26 22 58 54 22 26 22 53 65 2f } //1 :/"&"/w"&"w"&"w.e"&"n"&"s-s"&"et"&"if.d"&"z/a"&"nn"&"ua"&"ir"&"e/Y"&"u8"&"wj"&"HL"&"mA"&"zq"&"yU"&"S3"&"XT"&"Se/
		$a_01_4 = {3a 2f 22 26 22 2f 63 62 22 26 22 64 2e 63 22 26 22 6f 22 26 22 6d 2e 70 22 26 22 6b 2f 32 22 26 22 6d 22 26 22 79 30 22 26 22 66 61 22 26 22 74 2f 49 22 26 22 4f 70 22 26 22 34 2f } //1 :/"&"/cb"&"d.c"&"o"&"m.p"&"k/2"&"m"&"y0"&"fa"&"t/I"&"Op"&"4/
		$a_01_5 = {3a 2f 22 26 22 2f 68 61 22 26 22 66 73 22 26 22 74 22 26 22 72 6f 22 26 22 6d 2e 6e 22 26 22 75 2f 63 22 26 22 67 22 26 22 69 2d 62 22 26 22 69 22 26 22 6e 2f 71 22 26 22 59 52 22 26 22 30 55 22 26 22 51 61 22 26 22 43 4a 2f } //1 :/"&"/ha"&"fs"&"t"&"ro"&"m.n"&"u/c"&"g"&"i-b"&"i"&"n/q"&"YR"&"0U"&"Qa"&"CJ/
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=1
 
}