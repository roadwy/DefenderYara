
rule TrojanDownloader_O97M_Qakbot_PDG_MTB{
	meta:
		description = "TrojanDownloader:O97M/Qakbot.PDG!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 03 00 00 "
		
	strings :
		$a_01_0 = {3a 2f 2f 6d 75 73 22 26 22 74 61 66 22 26 22 61 6b 73 22 26 22 6f 79 2e 63 22 26 22 6f 22 26 22 6d 2f 55 4d 22 26 22 57 50 70 22 26 22 65 63 48 76 67 2f 67 6d 6b 6f 78 2e 70 22 26 22 6e 67 } //1 ://mus"&"taf"&"aks"&"oy.c"&"o"&"m/UM"&"WPp"&"ecHvg/gmkox.p"&"ng
		$a_01_1 = {3a 2f 2f 62 22 26 22 72 69 74 63 22 26 22 61 70 2e 63 22 26 22 6f 6d 2f 53 22 26 22 34 41 22 26 22 42 46 67 78 22 26 22 6e 57 22 26 22 4f 2f 67 6d 22 26 22 6b 6f 78 2e 70 22 26 22 6e 67 } //1 ://b"&"ritc"&"ap.c"&"om/S"&"4A"&"BFgx"&"nW"&"O/gm"&"kox.p"&"ng
		$a_01_2 = {3a 2f 2f 61 75 22 26 22 74 6f 70 6c 22 26 22 61 63 22 26 22 61 73 64 22 26 22 69 6c 22 26 22 67 65 72 2e 63 22 26 22 6f 6d 2e 62 22 26 22 72 2f 45 43 22 26 22 67 38 22 26 22 6d 36 22 26 22 6f 58 22 26 22 32 37 2f 67 6d 22 26 22 6b 6f 78 2e 70 22 26 22 6e 67 } //1 ://au"&"topl"&"ac"&"asd"&"il"&"ger.c"&"om.b"&"r/EC"&"g8"&"m6"&"oX"&"27/gm"&"kox.p"&"ng
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=1
 
}