
rule TrojanDownloader_O97M_Emotet_AEPD_MTB{
	meta:
		description = "TrojanDownloader:O97M/Emotet.AEPD!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 06 00 00 "
		
	strings :
		$a_01_0 = {3a 2f 2f 69 22 26 22 6c 72 69 22 26 22 70 22 26 22 61 72 22 26 22 61 74 22 26 22 75 74 22 26 22 74 6f 2e 65 22 26 22 75 2f 74 22 26 22 6d 22 26 22 70 2f 30 4b 22 26 22 31 4e 75 22 26 22 70 79 22 26 22 4b 50 22 26 22 65 58 2f } //1 ://i"&"lri"&"p"&"ar"&"at"&"ut"&"to.e"&"u/t"&"m"&"p/0K"&"1Nu"&"py"&"KP"&"eX/
		$a_01_1 = {3a 2f 2f 63 22 26 22 75 62 22 26 22 69 63 65 22 26 22 67 67 2e 61 22 26 22 73 22 26 22 69 61 2f 70 22 26 22 4b 55 22 26 22 56 51 22 26 22 73 66 22 26 22 53 48 22 26 22 42 2f 63 22 26 22 66 22 26 22 46 2f } //1 ://c"&"ub"&"ice"&"gg.a"&"s"&"ia/p"&"KU"&"VQ"&"sf"&"SH"&"B/c"&"f"&"F/
		$a_01_2 = {3a 2f 2f 64 22 26 22 72 76 22 26 22 69 6e 22 26 22 69 63 69 22 26 22 75 73 74 22 26 22 65 72 22 26 22 72 61 2e 63 22 26 22 6f 22 26 22 6d 2e 62 22 26 22 72 2f 77 22 26 22 70 2d 61 22 26 22 64 6d 22 26 22 69 6e 2f 5a 22 26 22 38 54 22 26 22 38 34 22 26 22 54 78 63 22 26 22 52 58 22 26 22 50 69 22 26 22 39 39 2f } //1 ://d"&"rv"&"in"&"ici"&"ust"&"er"&"ra.c"&"o"&"m.b"&"r/w"&"p-a"&"dm"&"in/Z"&"8T"&"84"&"Txc"&"RX"&"Pi"&"99/
		$a_01_3 = {3a 2f 2f 68 22 26 22 71 73 22 26 22 69 73 22 26 22 74 65 22 26 22 6d 61 22 26 22 73 2e 63 6f 22 26 22 6d 2e 61 22 26 22 72 2f 63 22 26 22 67 22 26 22 69 2d 62 22 26 22 69 6e 2f 46 22 26 22 4d 50 22 26 22 54 46 22 26 22 43 70 2f } //1 ://h"&"qs"&"is"&"te"&"ma"&"s.co"&"m.a"&"r/c"&"g"&"i-b"&"in/F"&"MP"&"TF"&"Cp/
		$a_01_4 = {3a 2f 2f 6a 69 22 26 22 6d 22 26 22 6d 79 6d 22 26 22 65 72 69 22 26 22 64 61 2e 69 22 26 22 6d 22 26 22 64 2e 63 22 26 22 6f 22 26 22 6d 2e 62 22 26 22 6f 2f 63 22 26 22 67 22 26 22 69 2d 62 22 26 22 69 6e 2f 6b 39 22 26 22 43 6e 22 26 22 6c 30 22 26 22 62 6b 2f } //1 ://ji"&"m"&"mym"&"eri"&"da.i"&"m"&"d.c"&"o"&"m.b"&"o/c"&"g"&"i-b"&"in/k9"&"Cn"&"l0"&"bk/
		$a_01_5 = {3a 2f 2f 63 22 26 22 65 69 22 26 22 62 61 22 26 22 64 69 73 22 26 22 65 6e 22 26 22 6f 2e 63 22 26 22 6f 22 26 22 6d 2e 6d 22 26 22 78 2f 62 72 22 26 22 6f 63 22 26 22 68 22 26 22 75 72 22 26 22 65 2f 68 22 26 22 6e 5a 6a 48 22 26 22 47 6f 22 26 22 31 45 22 26 22 59 49 54 22 26 22 51 5a 2f } //1 ://c"&"ei"&"ba"&"dis"&"en"&"o.c"&"o"&"m.m"&"x/br"&"oc"&"h"&"ur"&"e/h"&"nZjH"&"Go"&"1E"&"YIT"&"QZ/
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=1
 
}