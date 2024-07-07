
rule TrojanDownloader_O97M_Qakbot_PKJA_MTB{
	meta:
		description = "TrojanDownloader:O97M/Qakbot.PKJA!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 03 00 00 "
		
	strings :
		$a_03_0 = {74 63 6f 6d 6d 65 72 63 65 73 68 6f 70 2e 63 6f 6d 2f 90 02 14 2f 42 76 4d 6e 68 4f 6e 2e 70 6e 67 22 2c 22 90 00 } //1
		$a_03_1 = {64 63 72 69 61 63 6f 65 73 2e 63 6f 6d 2e 62 72 2f 90 02 14 2f 42 76 4d 6e 68 4f 6e 2e 70 6e 67 22 2c 22 90 00 } //1
		$a_03_2 = {63 6f 62 72 61 6d 6f 74 6f 73 2e 63 6f 6d 2e 62 72 2f 90 02 14 2f 42 76 4d 6e 68 4f 6e 2e 70 6e 67 22 2c 22 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=1
 
}
rule TrojanDownloader_O97M_Qakbot_PKJA_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/Qakbot.PKJA!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 03 00 00 "
		
	strings :
		$a_01_0 = {22 68 22 26 22 74 74 22 26 22 70 73 3a 2f 2f 67 72 6f 63 65 22 26 22 72 79 22 26 22 65 78 70 72 22 26 22 65 73 73 2e 6e 22 26 22 65 22 26 22 74 2f 44 32 41 22 26 22 47 79 53 4f 68 22 26 22 66 4e 45 22 26 22 5a 2f 65 22 26 22 74 79 2e 70 22 26 22 6e 67 22 2c 22 } //1 "h"&"tt"&"ps://groce"&"ry"&"expr"&"ess.n"&"e"&"t/D2A"&"GySOh"&"fNE"&"Z/e"&"ty.p"&"ng","
		$a_01_1 = {22 68 22 26 22 74 74 70 22 26 22 73 3a 2f 2f 70 72 6f 6a 22 26 22 65 76 61 6c 6c 22 26 22 65 2e 63 6f 22 26 22 6d 2e 62 72 2f 75 35 44 22 26 22 71 57 52 22 26 22 71 48 22 26 22 50 2f 65 74 79 2e 70 22 26 22 6e 67 22 2c 22 } //1 "h"&"ttp"&"s://proj"&"evall"&"e.co"&"m.br/u5D"&"qWR"&"qH"&"P/ety.p"&"ng","
		$a_01_2 = {22 68 22 26 22 74 74 70 22 26 22 73 3a 2f 2f 70 69 22 26 22 70 65 66 22 26 22 6c 6f 22 26 22 77 2e 63 22 26 22 6c 2f 4d 30 6d 22 26 22 34 78 30 22 26 22 48 4f 31 22 26 22 4e 51 22 26 22 4d 2f 65 22 26 22 74 79 2e 70 22 26 22 6e 67 22 2c 22 } //1 "h"&"ttp"&"s://pi"&"pef"&"lo"&"w.c"&"l/M0m"&"4x0"&"HO1"&"NQ"&"M/e"&"ty.p"&"ng","
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=1
 
}