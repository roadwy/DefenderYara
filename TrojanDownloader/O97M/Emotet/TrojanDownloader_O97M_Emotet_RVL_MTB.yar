
rule TrojanDownloader_O97M_Emotet_RVL_MTB{
	meta:
		description = "TrojanDownloader:O97M/Emotet.RVL!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 06 00 00 "
		
	strings :
		$a_01_0 = {2f 2f 6d 6f 61 70 72 69 6e 74 73 2e 63 6f 6d 2f 50 72 6d 61 33 48 6c 62 76 61 47 2f 22 2c 22 } //1 //moaprints.com/Prma3HlbvaG/","
		$a_01_1 = {2f 2f 6d 6f 68 61 6d 6d 61 64 79 61 72 69 63 6f 2e 63 6f 6d 2f 45 6e 67 6c 69 73 68 2f 6f 59 4a 46 36 34 64 63 47 4b 57 70 37 64 47 72 50 2f 22 2c 22 } //1 //mohammadyarico.com/English/oYJF64dcGKWp7dGrP/","
		$a_01_2 = {2f 2f 6b 72 6f 6e 6f 73 74 72 2e 63 6f 6d 2f 74 72 2f 4f 61 39 37 63 51 42 34 6c 34 43 6c 66 39 2f 22 2c 22 } //1 //kronostr.com/tr/Oa97cQB4l4Clf9/","
		$a_01_3 = {2f 2f 6e 61 74 64 65 6d 6f 2e 6e 61 74 72 69 78 73 6f 66 74 77 61 72 65 2e 63 6f 6d 2f 77 70 2d 61 64 6d 69 6e 2f 51 79 71 69 4e 2f 22 2c 22 } //1 //natdemo.natrixsoftware.com/wp-admin/QyqiN/","
		$a_01_4 = {2f 2f 6c 75 69 73 61 6e 67 65 6a 61 2e 63 6f 6d 2f 43 4f 50 59 52 49 47 48 54 2f 42 4a 6c 6a 66 66 47 36 2f 22 2c 22 } //1 //luisangeja.com/COPYRIGHT/BJljffG6/","
		$a_01_5 = {2f 2f 6e 65 72 7a 2e 6e 65 74 2f 73 74 61 74 73 2f 4b 56 49 79 6f 6f 4d 2f 22 2c 22 } //1 //nerz.net/stats/KVIyooM/","
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=1
 
}
rule TrojanDownloader_O97M_Emotet_RVL_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/Emotet.RVL!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 0c 00 00 "
		
	strings :
		$a_01_0 = {2f 2f 77 77 77 2e 6e 65 78 78 64 65 63 6f 72 2e 76 6e 2f 61 70 6b 2f 7a 79 38 47 6b 5a 2f 22 2c 22 } //1 //www.nexxdecor.vn/apk/zy8GkZ/","
		$a_01_1 = {2f 2f 70 61 6e 73 63 6f 6c 6c 65 63 74 69 6f 6e 73 2e 69 6e 2e 74 68 2f 61 73 73 65 74 73 2f 61 7a 48 4f 42 44 6f 75 78 2f 22 2c 22 } //1 //panscollections.in.th/assets/azHOBDoux/","
		$a_01_2 = {2f 2f 6e 22 26 22 61 74 22 26 22 69 6f 22 26 22 6e 63 22 26 22 6f 2d 6f 22 26 22 70 2e 6f 22 26 22 72 22 26 22 67 2f 63 22 26 22 73 22 26 22 73 2f 38 22 26 22 77 76 22 26 22 37 6c 22 26 22 42 35 2f 22 2c 22 } //1 //n"&"at"&"io"&"nc"&"o-o"&"p.o"&"r"&"g/c"&"s"&"s/8"&"wv"&"7l"&"B5/","
		$a_01_3 = {2f 2f 6c 22 26 22 69 67 22 26 22 68 74 22 26 22 6d 79 22 26 22 66 69 22 26 22 72 65 2e 69 22 26 22 6e 2f 64 22 26 22 65 22 26 22 6d 22 26 22 6f 2f 52 49 22 26 22 6b 41 22 26 22 46 67 54 46 56 75 61 49 30 35 72 32 2f 22 2c 22 } //1 //l"&"ig"&"ht"&"my"&"fi"&"re.i"&"n/d"&"e"&"m"&"o/RI"&"kA"&"FgTFVuaI05r2/","
		$a_01_4 = {2f 2f 70 61 70 69 6c 6c 6f 6e 77 65 62 2e 66 72 2f 77 70 2d 63 6f 6e 74 65 6e 74 2f 47 38 7a 30 38 71 30 6d 6a 2f 22 2c 22 } //1 //papillonweb.fr/wp-content/G8z08q0mj/","
		$a_01_5 = {2f 2f 62 72 65 6e 6e 61 6e 61 73 69 61 2e 63 6f 6d 2f 69 6d 61 67 65 73 2f 36 49 77 50 42 48 62 6e 55 76 66 67 75 67 56 31 62 2f 22 2c 22 } //1 //brennanasia.com/images/6IwPBHbnUvfgugV1b/","
		$a_01_6 = {2f 2f 65 73 74 61 63 69 6f 65 73 70 6f 72 74 69 76 61 76 69 6c 61 6e 6f 76 61 69 6c 61 67 65 6c 74 72 75 2e 63 61 74 2f 74 6d 70 2f 49 67 53 79 71 77 67 4a 6d 45 2f 22 2c 22 } //1 //estacioesportivavilanovailageltru.cat/tmp/IgSyqwgJmE/","
		$a_01_7 = {2f 2f 77 77 77 2e 73 75 70 65 72 73 61 6e 6d 75 74 66 61 6b 2e 63 6f 6d 2f 54 65 6d 70 6c 61 74 65 2f 4b 61 59 79 49 42 50 78 4d 75 6b 6a 6f 53 70 41 62 6a 2f 22 2c 22 } //1 //www.supersanmutfak.com/Template/KaYyIBPxMukjoSpAbj/","
		$a_01_8 = {2f 2f 76 69 70 65 73 63 6f 72 74 73 70 68 75 6b 65 74 2e 63 6f 6d 2f 61 73 73 65 74 73 2f 33 54 52 76 46 2f 22 2c 22 } //1 //vipescortsphuket.com/assets/3TRvF/","
		$a_01_9 = {2f 2f 76 74 6b 6c 69 6e 6b 65 72 77 65 72 6b 65 6e 2e 62 65 2f 6c 61 6e 67 75 61 67 65 2f 6c 6f 6a 4c 64 45 53 6e 63 56 2f 22 2c 22 } //1 //vtklinkerwerken.be/language/lojLdESncV/","
		$a_01_10 = {2f 2f 77 68 61 74 65 6c 6c 65 73 2e 6e 6c 2f 63 73 73 2f 4b 74 34 43 52 34 70 31 55 47 5a 47 51 6e 47 59 2f 22 2c 22 } //1 //whatelles.nl/css/Kt4CR4p1UGZGQnGY/","
		$a_01_11 = {2f 2f 77 77 77 2e 74 65 61 6d 73 61 76 65 2e 69 74 2f 41 48 30 4d 56 43 5a 35 2f 77 30 52 56 36 4c 73 5a 43 2f 22 2c 22 } //1 //www.teamsave.it/AH0MVCZ5/w0RV6LsZC/","
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1) >=1
 
}