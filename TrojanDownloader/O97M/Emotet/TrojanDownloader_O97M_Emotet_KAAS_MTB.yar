
rule TrojanDownloader_O97M_Emotet_KAAS_MTB{
	meta:
		description = "TrojanDownloader:O97M/Emotet.KAAS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 04 00 00 "
		
	strings :
		$a_01_0 = {3a 2f 2f 77 77 77 2e 7a 61 72 64 61 6d 61 72 69 6e 65 2e 63 6f 6d 2f 69 6d 61 67 65 73 2f 70 73 51 62 41 6a 72 72 45 4f 58 57 50 72 53 2f } //1 ://www.zardamarine.com/images/psQbAjrrEOXWPrS/
		$a_01_1 = {3a 2f 2f 6c 61 62 66 69 74 6f 75 74 73 2e 63 6f 6d 2f 63 67 69 2d 62 69 6e 2f 52 65 61 33 49 75 33 77 47 76 67 41 62 54 73 65 74 30 2f } //1 ://labfitouts.com/cgi-bin/Rea3Iu3wGvgAbTset0/
		$a_01_2 = {3a 2f 2f 6b 22 26 22 72 6f 22 26 22 6e 22 26 22 6f 73 22 26 22 74 72 2e 63 22 26 22 6f 22 26 22 6d 2f 74 72 2f 36 22 26 22 38 79 22 26 22 48 52 22 26 22 68 66 22 26 22 75 22 26 22 55 37 22 26 22 51 6a 2f } //1 ://k"&"ro"&"n"&"os"&"tr.c"&"o"&"m/tr/6"&"8y"&"HR"&"hf"&"u"&"U7"&"Qj/
		$a_01_3 = {3a 2f 2f 74 65 6b 22 26 22 73 74 69 6c 75 22 26 22 7a 6d 61 22 26 22 6e 67 22 26 22 6f 72 22 26 22 75 73 22 26 22 75 2e 63 22 26 22 6f 22 26 22 6d 2f 77 22 26 22 70 2d 61 22 26 22 64 6d 22 26 22 69 6e 2f 47 22 26 22 4b 64 22 26 22 51 76 22 26 22 61 6d 22 26 22 6e 50 22 26 22 63 4b 2f 22 2c 22 } //1 ://tek"&"stilu"&"zma"&"ng"&"or"&"us"&"u.c"&"o"&"m/w"&"p-a"&"dm"&"in/G"&"Kd"&"Qv"&"am"&"nP"&"cK/","
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=1
 
}