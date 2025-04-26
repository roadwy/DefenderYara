
rule TrojanDownloader_O97M_Emotet_RVV_MTB{
	meta:
		description = "TrojanDownloader:O97M/Emotet.RVV!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 03 00 00 "
		
	strings :
		$a_01_0 = {69 22 26 22 6e 6e 22 26 22 69 6e 22 26 22 67 2f 4e 22 26 22 67 6d 22 26 22 42 48 22 26 22 34 38 22 26 22 47 43 22 26 22 7a 6f 22 26 22 76 45 22 26 22 49 41 22 26 22 67 4a 22 26 22 59 2f } //1 i"&"nn"&"in"&"g/N"&"gm"&"BH"&"48"&"GC"&"zo"&"vE"&"IA"&"gJ"&"Y/
		$a_01_1 = {6f 22 26 22 6d 2f 22 26 22 72 61 22 26 22 6e 64 5f 69 22 26 22 6d 61 22 26 22 67 65 22 26 22 73 2f 4e 22 26 22 54 35 22 26 22 4e 6a 22 26 22 4b 36 22 26 22 6f 2f } //1 o"&"m/"&"ra"&"nd_i"&"ma"&"ge"&"s/N"&"T5"&"Nj"&"K6"&"o/
		$a_01_2 = {6e 22 26 22 2f 77 22 26 22 70 2d 61 22 26 22 64 6d 22 26 22 69 6e 2f 63 22 26 22 62 2f } //1 n"&"/w"&"p-a"&"dm"&"in/c"&"b/
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=1
 
}