
rule TrojanDownloader_O97M_Emotet_SSMK_MTB{
	meta:
		description = "TrojanDownloader:O97M/Emotet.SSMK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 3a 2f 2f 68 65 6e 72 79 73 66 72 65 73 68 72 6f 61 73 74 2e 63 6f 6d 2f 4f 65 76 49 37 59 79 30 69 36 59 53 68 78 46 6c 2f } //2 http://henrysfreshroast.com/OevI7Yy0i6YShxFl/
		$a_01_1 = {68 74 74 70 3a 2f 2f 77 77 77 2e 61 6a 61 78 6d 61 74 74 65 72 73 2e 63 6f 6d 2f 63 37 67 38 74 2f 6e 6e 7a 4a 4a 31 72 4b 46 44 32 50 2f } //2 http://www.ajaxmatters.com/c7g8t/nnzJJ1rKFD2P/
		$a_01_2 = {68 74 74 70 3a 2f 2f 61 6f 70 64 61 2e 6f 72 67 2f 77 70 2d 63 6f 6e 74 65 6e 74 2f 75 70 6c 6f 61 64 73 2f 35 6f 54 41 56 4a 79 6a 44 46 4f 6c 6c 58 32 75 45 2f } //2 http://aopda.org/wp-content/uploads/5oTAVJyjDFOllX2uE/
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=2
 
}
rule TrojanDownloader_O97M_Emotet_SSMK_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/Emotet.SSMK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 05 00 00 "
		
	strings :
		$a_01_0 = {67 61 6e 64 68 69 74 6f 64 61 79 2e 6f 72 67 2f 76 69 64 65 6f 2f 36 4a 76 41 38 2f } //1 gandhitoday.org/video/6JvA8/
		$a_01_1 = {64 6a 75 6e 72 65 61 6c 2e 63 6f 2e 75 6b 2f 73 69 74 65 2f 41 70 4f 4b 70 46 61 64 2f } //1 djunreal.co.uk/site/ApOKpFad/
		$a_01_2 = {6a 6f 68 6e 73 6f 6e 73 6d 65 64 69 61 2e 69 74 2f 69 6d 67 2f 5a 42 4e 6b 30 78 70 52 4c 38 59 45 56 6c } //1 johnsonsmedia.it/img/ZBNk0xpRL8YEVl
		$a_01_3 = {67 65 6e 63 63 61 67 64 61 73 2e 63 6f 6d 2e 74 72 2f 61 73 73 65 74 73 2f 64 6f 57 48 49 78 4c 65 37 65 } //1 genccagdas.com.tr/assets/doWHIxLe7e
		$a_01_4 = {67 72 61 66 69 73 63 68 65 72 2e 63 68 2f 66 69 74 2d 77 65 6c 6c 2f 77 44 50 54 77 4b 74 5a 50 6f 57 4c 31 32 2f } //1 grafischer.ch/fit-well/wDPTwKtZPoWL12/
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=1
 
}
rule TrojanDownloader_O97M_Emotet_SSMK_MTB_3{
	meta:
		description = "TrojanDownloader:O97M/Emotet.SSMK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 06 00 00 "
		
	strings :
		$a_01_0 = {3a 2f 2f 6d 79 6d 69 63 72 6f 67 72 65 65 6e 2e 6d 69 67 68 74 63 6f 64 65 2e 63 6f 6d 2f 46 6f 78 2d 43 2f 68 6c 48 56 2f } //1 ://mymicrogreen.mightcode.com/Fox-C/hlHV/
		$a_01_1 = {3a 2f 2f 31 38 38 2e 31 36 36 2e 5d 32 34 35 2e 31 31 32 2f 74 65 6d 70 6c 61 74 65 2f 52 79 6b 2f } //1 ://188.166.]245.112/template/Ryk/
		$a_01_2 = {3a 2f 2f 34 37 2e 5d 32 34 34 2e 31 38 39 2e 5d 37 33 2f 2d 2d 2f 65 72 32 79 41 35 4c 6b 52 63 58 72 54 30 51 2f } //1 ://47.]244.189.]73/--/er2yA5LkRcXrT0Q/
		$a_01_3 = {3a 2f 2f 77 77 77 2e 64 6e 61 75 74 69 6b 2e 63 6f 6d 2f 77 70 2d 69 6e 63 6c 75 64 65 73 2f 76 54 41 52 48 52 4b 48 6a 52 71 6b 47 4b 55 2f } //1 ://www.dnautik.com/wp-includes/vTARHRKHjRqkGKU/
		$a_01_4 = {3a 2f 2f 61 6c 2d 62 72 69 6b 2e 63 6f 6d 2f 76 62 2f 45 42 42 37 46 75 61 57 6e 4a 6d 2f } //1 ://al-brik.com/vb/EBB7FuaWnJm/
		$a_01_5 = {3a 2f 2f 62 75 6c 6c 64 6f 67 69 72 6f 6e 77 6f 72 6b 73 6c 6c 63 2e 63 6f 6d 2f 74 65 6d 70 2f 36 55 79 4e 75 38 2f } //1 ://bulldogironworksllc.com/temp/6UyNu8/
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=1
 
}
rule TrojanDownloader_O97M_Emotet_SSMK_MTB_4{
	meta:
		description = "TrojanDownloader:O97M/Emotet.SSMK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 06 00 00 "
		
	strings :
		$a_01_0 = {3a 2f 2f 63 72 65 65 6d 6f 2e 70 6c 2f 77 70 2d 61 64 6d 69 6e 2f 5a 4b 53 31 44 63 64 71 75 55 54 34 42 62 38 4b 62 2f } //1 ://creemo.pl/wp-admin/ZKS1DcdquUT4Bb8Kb/
		$a_01_1 = {3a 2f 2f 66 69 6c 6d 6d 6f 67 7a 69 76 6f 74 61 2e 72 73 2f 53 70 72 79 41 73 73 65 74 73 2f 67 44 52 2f } //1 ://filmmogzivota.rs/SpryAssets/gDR/
		$a_01_2 = {3a 2f 2f 64 65 6d 6f 33 34 2e 63 6b 67 2e 68 6b 2f 73 65 72 76 69 63 65 2f 68 68 4d 5a 72 66 43 37 4d 6e 6d 39 4a 44 2f } //1 ://demo34.ckg.hk/service/hhMZrfC7Mnm9JD/
		$a_01_3 = {3a 2f 2f 66 6f 63 75 73 6d 65 64 69 63 61 2e 69 6e 2f 66 6d 6c 69 62 2f 49 78 42 41 42 4d 68 30 49 32 63 4c 4d 33 71 71 31 47 56 76 2f } //1 ://focusmedica.in/fmlib/IxBABMh0I2cLM3qq1GVv/
		$a_01_4 = {3a 2f 2f 63 69 70 72 6f 2e 6d 78 2f 70 72 65 6e 73 61 2f 73 69 5a 50 36 39 72 42 46 6d 69 62 44 76 75 54 50 31 4c 2f } //1 ://cipro.mx/prensa/siZP69rBFmibDvuTP1L/
		$a_01_5 = {3a 2f 2f 63 6f 6c 65 67 69 6f 75 6e 61 6d 75 6e 6f 2e 65 73 2f 63 67 69 2d 62 69 6e 2f 45 2f } //1 ://colegiounamuno.es/cgi-bin/E/
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=1
 
}
rule TrojanDownloader_O97M_Emotet_SSMK_MTB_5{
	meta:
		description = "TrojanDownloader:O97M/Emotet.SSMK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 03 00 00 "
		
	strings :
		$a_01_0 = {74 22 26 22 74 22 26 22 70 22 26 22 73 22 26 22 3a 2f 22 26 22 2f 69 22 26 22 6d 22 26 22 6d 22 26 22 6f 62 22 26 22 69 6c 67 22 26 22 6f 6c 66 22 26 22 6f 2e 69 74 2f 63 22 26 22 67 22 26 22 69 2d 62 22 26 22 69 22 26 22 6e 2f 55 66 22 26 } //1 t"&"t"&"p"&"s"&":/"&"/i"&"m"&"m"&"ob"&"ilg"&"olf"&"o.it/c"&"g"&"i-b"&"i"&"n/Uf"&
		$a_01_1 = {74 22 26 22 74 22 26 22 70 22 26 22 3a 2f 22 26 22 2f 69 22 26 22 6c 73 22 26 22 65 77 22 26 22 65 6c 22 26 22 70 2e 6e 22 26 22 6c 2f 74 22 26 22 65 6d 22 26 22 70 6c 22 26 22 61 74 22 26 22 65 73 2f 63 22 26 22 39 42 22 26 22 35 39 22 26 22 6a 50 22 26 22 37 7a 22 26 22 73 2f } //1 t"&"t"&"p"&":/"&"/i"&"ls"&"ew"&"el"&"p.n"&"l/t"&"em"&"pl"&"at"&"es/c"&"9B"&"59"&"jP"&"7z"&"s/
		$a_01_2 = {74 22 26 22 74 22 26 22 70 22 26 22 3a 2f 22 26 22 2f 69 6e 22 26 22 64 6f 22 26 22 6e 65 22 26 22 73 69 22 26 22 61 6a 75 22 26 22 61 72 22 26 22 61 2e 61 22 26 22 73 69 22 26 22 61 2f 77 22 26 22 70 2d 63 22 26 22 6f 6e 22 26 22 74 65 22 26 22 6e 22 26 22 74 2f 78 2f } //1 t"&"t"&"p"&":/"&"/in"&"do"&"ne"&"si"&"aju"&"ar"&"a.a"&"si"&"a/w"&"p-c"&"on"&"te"&"n"&"t/x/
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=1
 
}
rule TrojanDownloader_O97M_Emotet_SSMK_MTB_6{
	meta:
		description = "TrojanDownloader:O97M/Emotet.SSMK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 06 00 00 "
		
	strings :
		$a_01_0 = {74 74 70 73 3a 2f 2f 68 65 70 73 69 73 69 66 61 2e 63 6f 6d 2f 77 70 2d 61 64 6d 69 6e 2f 6b 2f } //1 ttps://hepsisifa.com/wp-admin/k/
		$a_01_1 = {74 74 70 3a 2f 2f 66 69 6c 6d 6d 6f 67 7a 69 76 6f 74 61 2e 72 73 2f 53 70 72 79 41 73 73 65 74 73 2f 6f 72 32 34 68 68 42 6c 32 49 62 38 37 30 34 53 44 4f 2f } //1 ttp://filmmogzivota.rs/SpryAssets/or24hhBl2Ib8704SDO/
		$a_01_2 = {74 74 70 3a 2f 2f 65 63 6f 61 72 63 68 2e 63 6f 6d 2e 74 77 2f 63 67 69 2d 62 69 6e 2f 45 2f } //1 ttp://ecoarch.com.tw/cgi-bin/E/
		$a_01_3 = {74 74 70 73 3a 2f 2f 77 77 77 2e 63 6c 65 61 72 63 6f 6e 73 74 72 75 63 74 69 6f 6e 2e 63 6f 2e 75 6b 2f 73 63 72 69 70 74 73 2f 45 76 35 49 58 6f 42 76 46 4a 6b 42 51 30 4d 5a 58 62 2f } //1 ttps://www.clearconstruction.co.uk/scripts/Ev5IXoBvFJkBQ0MZXb/
		$a_01_4 = {74 74 70 73 3a 2f 2f 67 61 6c 61 78 79 2d 63 61 74 65 72 69 6e 67 2e 63 6f 6d 2e 76 6e 2f 67 61 6c 78 79 2f 46 67 31 76 76 68 6c 59 4a 2f } //1 ttps://galaxy-catering.com.vn/galxy/Fg1vvhlYJ/
		$a_01_5 = {74 74 70 3a 2f 2f 77 77 77 2e 68 61 6e 67 61 72 79 61 70 69 2e 63 6f 6d 2e 74 72 2f 77 70 2d 61 64 6d 69 6e 2f 35 6e 34 32 6e 63 4c 33 6e 57 4d 62 4a 48 77 79 37 2f } //1 ttp://www.hangaryapi.com.tr/wp-admin/5n42ncL3nWMbJHwy7/
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=1
 
}
rule TrojanDownloader_O97M_Emotet_SSMK_MTB_7{
	meta:
		description = "TrojanDownloader:O97M/Emotet.SSMK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 06 00 00 "
		
	strings :
		$a_01_0 = {74 74 70 73 3a 2f 2f 77 77 77 2e 69 74 65 73 6d 65 69 74 69 63 2e 63 6f 6d 2f 74 65 72 6d 2f 49 46 6a 78 35 45 6c 45 30 6c 64 72 38 77 44 44 48 6a 75 62 2f } //1 ttps://www.itesmeitic.com/term/IFjx5ElE0ldr8wDDHjub/
		$a_01_1 = {74 74 70 73 3a 2f 2f 77 77 77 2e 69 6e 67 6f 6e 68 65 72 62 61 6c 2e 63 6f 6d 2f 61 70 70 6c 69 63 61 74 69 6f 6e 2f 50 68 45 62 63 65 67 34 78 2f } //1 ttps://www.ingonherbal.com/application/PhEbceg4x/
		$a_01_2 = {74 74 70 3a 2f 2f 66 74 70 2e 63 6f 6c 69 62 72 69 63 6f 6e 73 74 72 75 63 74 69 6f 6e 2e 6e 65 74 2f 63 63 2f 4b 48 69 65 71 65 4f 73 61 67 6b 6d 6c 47 49 75 58 63 35 36 2f } //1 ttp://ftp.colibriconstruction.net/cc/KHieqeOsagkmlGIuXc56/
		$a_01_3 = {74 74 70 3a 2f 2f 63 6f 6d 6d 75 6e 65 2d 61 72 69 61 6e 61 2e 74 6e 2f 73 69 74 65 73 2f 33 42 76 61 43 6d 6f 2f } //1 ttp://commune-ariana.tn/sites/3BvaCmo/
		$a_01_4 = {74 74 70 3a 2f 2f 64 6d 61 69 63 69 6e 6e 6f 76 61 74 69 6f 6e 73 2e 63 6f 6d 2f 53 77 69 66 74 2d 35 2e 30 2e 32 2f 6a 45 74 65 50 42 2f } //1 ttp://dmaicinnovations.com/Swift-5.0.2/jEtePB/
		$a_01_5 = {74 74 70 73 3a 2f 2f 64 72 63 72 65 61 74 69 76 65 2e 63 7a 2f 69 6d 61 67 65 73 2f 44 77 54 68 79 51 6e 74 79 49 6d 43 48 6b 30 74 70 62 61 2f } //1 ttps://drcreative.cz/images/DwThyQntyImCHk0tpba/
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=1
 
}
rule TrojanDownloader_O97M_Emotet_SSMK_MTB_8{
	meta:
		description = "TrojanDownloader:O97M/Emotet.SSMK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 05 00 00 "
		
	strings :
		$a_01_0 = {68 22 26 22 74 74 22 26 22 70 73 3a 2f 22 26 22 2f 62 22 26 22 76 69 22 26 22 72 74 22 26 22 75 61 22 26 22 6c 2e 63 22 26 22 6f 22 26 22 6d 2f 61 22 26 22 66 66 22 26 22 69 6e 22 26 22 69 74 22 26 22 61 2f 72 22 26 22 79 58 22 26 22 55 5a 22 26 22 64 41 22 26 22 48 63 22 26 22 4e 4e 22 26 22 45 47 2f } //1 h"&"tt"&"ps:/"&"/b"&"vi"&"rt"&"ua"&"l.c"&"o"&"m/a"&"ff"&"in"&"it"&"a/r"&"yX"&"UZ"&"dA"&"Hc"&"NN"&"EG/
		$a_01_1 = {68 22 26 22 74 74 22 26 22 70 22 26 22 73 3a 2f 22 26 22 2f 62 75 22 26 22 6c 6c 22 26 22 64 6f 22 26 22 67 69 22 26 22 72 6f 22 26 22 6e 77 22 26 22 6f 72 22 26 22 6b 73 22 26 22 6c 6c 22 26 22 63 2e 63 22 26 22 6f 22 26 22 6d 2f 74 22 26 22 65 6d 22 26 22 70 2f 33 22 26 22 32 39 22 26 22 33 30 22 26 22 52 6f 22 26 22 6f 66 22 26 22 62 64 22 26 22 6d 51 22 26 22 30 72 } //1 h"&"tt"&"p"&"s:/"&"/bu"&"ll"&"do"&"gi"&"ro"&"nw"&"or"&"ks"&"ll"&"c.c"&"o"&"m/t"&"em"&"p/3"&"29"&"30"&"Ro"&"of"&"bd"&"mQ"&"0r
		$a_01_2 = {68 22 26 22 74 74 22 26 22 70 73 3a 2f 22 26 22 2f 77 22 26 22 77 77 2e 61 22 26 22 6c 6d 22 26 22 6f 65 22 26 22 71 61 22 26 22 74 61 22 26 22 72 2e 63 22 26 22 6f 22 26 22 6d 2f 63 22 26 22 67 22 26 22 69 2d 62 22 26 22 69 6e 2f 71 22 26 22 6f 4f 22 26 22 59 50 22 26 22 68 6c 22 26 22 6b 52 22 26 22 47 6e 22 26 22 42 43 22 26 22 6c 6d 22 26 22 4e 75 22 26 22 35 49 2f 57 } //1 h"&"tt"&"ps:/"&"/w"&"ww.a"&"lm"&"oe"&"qa"&"ta"&"r.c"&"o"&"m/c"&"g"&"i-b"&"in/q"&"oO"&"YP"&"hl"&"kR"&"Gn"&"BC"&"lm"&"Nu"&"5I/W
		$a_01_3 = {68 22 26 22 74 74 22 26 22 70 73 3a 2f 22 26 22 2f 62 6f 22 26 22 73 6e 22 26 22 79 2e 63 22 26 22 6f 22 26 22 6d 2f 61 22 26 22 73 70 22 26 22 6e 65 22 26 22 74 5f 63 22 26 22 6c 69 22 26 22 65 6e 22 26 22 74 2f 55 22 26 22 5a 6c 22 26 22 73 74 22 26 22 } //1 h"&"tt"&"ps:/"&"/bo"&"sn"&"y.c"&"o"&"m/a"&"sp"&"ne"&"t_c"&"li"&"en"&"t/U"&"Zl"&"st"&"
		$a_01_4 = {68 22 26 22 74 74 22 26 22 70 3a 2f 22 26 22 2f 6d 75 22 26 22 6c 6d 22 26 22 61 74 22 26 22 64 6f 22 26 22 6c 2e 63 22 26 22 6f 22 26 22 6d 2f 61 22 26 22 64 22 26 22 6d 2f 53 22 26 22 65 6d 22 26 22 72 78 22 26 22 36 70 22 26 22 51 2f } //1 h"&"tt"&"p:/"&"/mu"&"lm"&"at"&"do"&"l.c"&"o"&"m/a"&"d"&"m/S"&"em"&"rx"&"6p"&"Q/
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=1
 
}
rule TrojanDownloader_O97M_Emotet_SSMK_MTB_9{
	meta:
		description = "TrojanDownloader:O97M/Emotet.SSMK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 06 00 00 "
		
	strings :
		$a_01_0 = {68 22 26 22 74 74 22 26 22 70 3a 2f 22 26 22 2f 64 6f 22 26 22 75 22 26 22 67 22 26 22 76 65 22 26 22 65 64 22 26 22 65 72 2e 63 22 26 22 6f 22 26 22 6d 2f 63 22 26 22 67 22 26 22 69 2d 62 22 26 22 69 22 26 22 6e 2f 78 4a 22 26 22 39 31 22 26 22 5a 74 22 26 22 74 47 22 26 22 52 69 22 26 22 6f 51 22 26 22 37 49 22 26 22 55 4c 2f } //1 h"&"tt"&"p:/"&"/do"&"u"&"g"&"ve"&"ed"&"er.c"&"o"&"m/c"&"g"&"i-b"&"i"&"n/xJ"&"91"&"Zt"&"tG"&"Ri"&"oQ"&"7I"&"UL/
		$a_01_1 = {68 22 26 22 74 74 70 22 26 22 73 3a 2f 22 26 22 2f 65 2d 66 69 22 26 22 73 74 22 26 22 69 6b 2e 63 22 26 22 6f 22 26 22 6d 2f 61 22 26 22 6a 61 22 26 22 78 2f 50 22 26 22 6e 41 } //1 h"&"ttp"&"s:/"&"/e-fi"&"st"&"ik.c"&"o"&"m/a"&"ja"&"x/P"&"nA
		$a_01_2 = {68 22 26 22 74 74 22 26 22 70 3a 2f 22 26 22 2f 64 73 22 26 22 69 6e 22 26 22 66 6f 22 26 22 72 6d 22 26 22 61 74 22 26 22 69 63 22 26 22 6f 22 26 22 73 2e 63 22 26 22 6f 22 26 22 6d 2f 5f 70 22 26 22 72 69 22 26 22 76 61 22 26 22 74 65 2f 66 22 26 22 33 36 22 26 22 59 6c } //1 h"&"tt"&"p:/"&"/ds"&"in"&"fo"&"rm"&"at"&"ic"&"o"&"s.c"&"o"&"m/_p"&"ri"&"va"&"te/f"&"36"&"Yl
		$a_01_3 = {68 22 26 22 74 74 22 26 22 70 3a 2f 22 26 22 2f 64 73 22 26 22 74 6e 22 26 22 79 2e 6e 22 26 22 65 22 26 22 74 2f 63 22 26 22 67 22 26 22 69 2d 62 22 26 22 69 22 26 22 6e 2f 50 22 26 22 4f 71 22 26 22 4a 4b 22 26 22 63 78 22 26 22 69 49 22 26 22 7a 52 22 26 22 62 } //1 h"&"tt"&"p:/"&"/ds"&"tn"&"y.n"&"e"&"t/c"&"g"&"i-b"&"i"&"n/P"&"Oq"&"JK"&"cx"&"iI"&"zR"&"b
		$a_01_4 = {68 22 26 22 74 74 22 26 22 70 3a 2f 22 26 22 2f 66 61 22 26 22 6b 65 22 26 22 63 69 22 26 22 74 79 2e 6e 22 26 22 65 22 26 22 74 2f 63 22 26 22 61 63 22 26 22 68 65 2f 58 22 26 22 74 49 22 26 22 7a 68 22 26 22 79 4c 22 26 22 45 6f 22 26 22 4c 49 } //1 h"&"tt"&"p:/"&"/fa"&"ke"&"ci"&"ty.n"&"e"&"t/c"&"ac"&"he/X"&"tI"&"zh"&"yL"&"Eo"&"LI
		$a_01_5 = {68 22 26 22 74 74 22 26 22 70 3a 2f 22 26 22 2f 66 61 22 26 22 79 65 22 26 22 73 63 22 26 22 68 6d 22 26 22 69 64 22 26 22 74 2e 63 22 26 22 6f 22 26 22 6d 2f 63 22 26 22 67 22 26 22 69 2d 62 22 26 22 69 22 26 22 6e 2f 51 22 26 22 38 70 22 26 22 6a } //1 h"&"tt"&"p:/"&"/fa"&"ye"&"sc"&"hm"&"id"&"t.c"&"o"&"m/c"&"g"&"i-b"&"i"&"n/Q"&"8p"&"j
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=1
 
}