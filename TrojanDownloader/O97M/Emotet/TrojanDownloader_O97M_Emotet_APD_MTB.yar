
rule TrojanDownloader_O97M_Emotet_APD_MTB{
	meta:
		description = "TrojanDownloader:O97M/Emotet.APD!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {3a 2f 2f 77 22 26 22 77 22 26 22 77 2e 62 73 61 22 26 22 67 72 6f 22 26 22 75 22 26 22 70 2e 63 22 26 22 6f 22 26 22 6d 2e 62 22 26 22 72 2f 63 61 74 2e 70 22 26 22 68 22 26 22 70 } //1 ://w"&"w"&"w.bsa"&"gro"&"u"&"p.c"&"o"&"m.b"&"r/cat.p"&"h"&"p
	condition:
		((#a_01_0  & 1)*1) >=1
 
}