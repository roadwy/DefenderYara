
rule TrojanDownloader_O97M_Emotet_VDSM_MTB{
	meta:
		description = "TrojanDownloader:O97M/Emotet.VDSM!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 04 00 00 "
		
	strings :
		$a_01_0 = {77 22 26 22 65 22 26 22 62 34 22 26 22 6e 6f 22 26 22 74 68 22 26 22 69 6e 22 26 22 67 2e 63 22 26 22 6f 22 26 22 6d 2f 63 22 26 22 67 22 26 22 69 2d 62 22 26 22 69 6e 2f 78 73 22 26 22 4b 75 42 4b 22 26 22 75 51 22 26 22 59 68 22 26 22 59 7a 2f } //1 w"&"e"&"b4"&"no"&"th"&"in"&"g.c"&"o"&"m/c"&"g"&"i-b"&"in/xs"&"KuBK"&"uQ"&"Yh"&"Yz/
		$a_01_1 = {76 22 26 22 69 65 22 26 22 74 72 22 26 22 6f 6c 22 26 22 6c 2e 76 22 26 22 6e 2f 77 22 26 22 70 2d 63 6f 22 26 22 6e 74 22 26 22 65 22 26 22 6e 74 2f 6b 22 26 22 39 74 22 26 22 53 54 69 22 26 22 57 31 22 26 22 43 6f 22 26 22 73 4b 22 26 22 59 4a 4f 6a 22 26 22 78 64 2f } //1 v"&"ie"&"tr"&"ol"&"l.v"&"n/w"&"p-co"&"nt"&"e"&"nt/k"&"9t"&"STi"&"W1"&"Co"&"sK"&"YJOj"&"xd/
		$a_01_2 = {31 22 26 22 33 22 26 22 36 2e 32 22 26 22 34 22 26 22 33 2e 32 22 26 22 31 22 26 22 37 2e 32 22 26 22 35 22 26 22 30 2f 61 22 26 22 70 70 22 26 22 6c 69 63 61 22 26 22 74 69 22 26 22 6f 6e 2f 4f 50 34 22 26 22 4c 37 22 26 22 4d 56 32 31 22 26 22 68 62 22 26 22 75 62 22 26 22 34 2f } //1 1"&"3"&"6.2"&"4"&"3.2"&"1"&"7.2"&"5"&"0/a"&"pp"&"lica"&"ti"&"on/OP4"&"L7"&"MV21"&"hb"&"ub"&"4/
		$a_01_3 = {77 22 26 22 65 62 22 26 22 70 61 22 26 22 72 74 22 26 22 6e 65 22 26 22 72 2e 66 22 26 22 72 2f 6c 22 26 22 61 6e 22 26 22 67 75 22 26 22 61 67 22 26 22 65 2f 6d 22 26 22 54 62 49 48 22 26 22 4c 32 50 22 26 22 31 32 22 26 22 75 4a 22 26 22 33 4d 22 26 22 4a 6c 22 26 22 4c 2f } //1 w"&"eb"&"pa"&"rt"&"ne"&"r.f"&"r/l"&"an"&"gu"&"ag"&"e/m"&"TbIH"&"L2P"&"12"&"uJ"&"3M"&"Jl"&"L/
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=1
 
}