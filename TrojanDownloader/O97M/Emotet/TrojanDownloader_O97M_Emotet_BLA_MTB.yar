
rule TrojanDownloader_O97M_Emotet_BLA_MTB{
	meta:
		description = "TrojanDownloader:O97M/Emotet.BLA!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 04 00 00 "
		
	strings :
		$a_01_0 = {77 22 26 22 77 22 26 22 77 2e 62 22 26 22 65 72 22 26 22 65 6b 22 26 22 65 74 22 26 22 68 61 22 26 22 62 65 22 26 22 72 2e 63 22 26 22 6f 22 26 22 6d 2f 68 22 26 22 61 74 22 26 22 61 78 2f 66 22 26 22 6f 76 22 26 22 4c 61 22 26 22 72 6f } //1 w"&"w"&"w.b"&"er"&"ek"&"et"&"ha"&"be"&"r.c"&"o"&"m/h"&"at"&"ax/f"&"ov"&"La"&"ro
		$a_01_1 = {62 22 26 22 6f 73 22 26 22 6e 79 2e 63 22 26 22 6f 22 26 22 6d 2f 61 22 26 22 73 70 22 26 22 6e 65 22 26 22 74 5f 63 6c 22 26 22 69 65 22 26 22 6e 74 2f 45 22 26 22 72 49 35 22 26 22 46 37 34 22 26 22 63 77 22 26 22 69 69 22 26 22 4f 79 22 26 22 77 65 } //1 b"&"os"&"ny.c"&"o"&"m/a"&"sp"&"ne"&"t_cl"&"ie"&"nt/E"&"rI5"&"F74"&"cw"&"ii"&"Oy"&"we
		$a_01_2 = {77 22 26 22 77 22 26 22 77 2e 63 22 26 22 65 73 22 26 22 61 73 22 26 22 69 6e 2e 63 22 26 22 6f 22 26 22 6d 2e 61 22 26 22 72 2f 61 64 22 26 22 6d 69 22 26 22 6e 69 22 26 22 73 74 72 22 26 22 61 74 22 26 22 6f 72 2f 48 22 26 22 43 34 36 22 26 22 6b 48 22 26 22 44 55 22 26 22 53 59 22 26 22 4e 33 22 26 22 30 35 22 26 22 47 67 22 26 22 6c 43 22 26 22 50 } //1 w"&"w"&"w.c"&"es"&"as"&"in.c"&"o"&"m.a"&"r/ad"&"mi"&"ni"&"str"&"at"&"or/H"&"C46"&"kH"&"DU"&"SY"&"N3"&"05"&"Gg"&"lC"&"P
		$a_01_3 = {62 22 26 22 65 6e 22 26 22 63 65 22 26 22 76 65 22 26 22 6e 64 22 26 22 65 67 22 26 22 68 61 22 26 22 7a 2e 68 75 2f 77 22 26 22 70 2d 69 6e 22 26 22 63 6c 22 26 22 75 64 22 26 22 65 73 2f 74 22 26 22 58 51 22 26 22 42 73 22 26 22 67 6c 22 26 22 4e 4f 22 26 22 49 73 22 26 22 75 6e 22 26 22 6b } //1 b"&"en"&"ce"&"ve"&"nd"&"eg"&"ha"&"z.hu/w"&"p-in"&"cl"&"ud"&"es/t"&"XQ"&"Bs"&"gl"&"NO"&"Is"&"un"&"k
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=1
 
}