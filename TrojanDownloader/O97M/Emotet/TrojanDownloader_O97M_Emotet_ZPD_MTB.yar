
rule TrojanDownloader_O97M_Emotet_ZPD_MTB{
	meta:
		description = "TrojanDownloader:O97M/Emotet.ZPD!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {3a 2f 22 26 22 2f 77 22 26 22 69 66 22 26 22 69 2e 68 22 26 22 6f 74 22 26 22 73 70 22 26 22 6f 74 2e 6d 67 2f 6a 22 26 22 73 2f 78 22 26 22 65 37 22 26 22 30 7a 22 26 22 77 38 2f } //01 00  :/"&"/w"&"if"&"i.h"&"ot"&"sp"&"ot.mg/j"&"s/x"&"e7"&"0z"&"w8/
		$a_01_1 = {3a 2f 22 26 22 2f 69 6b 22 26 22 61 74 22 26 22 65 6d 22 26 22 69 61 2e 75 22 26 22 6e 74 22 26 22 69 72 22 26 22 74 61 2e 61 22 26 22 63 2e 69 22 26 22 64 2f 61 22 26 22 73 22 26 22 73 65 22 26 22 74 73 2f 56 22 26 22 54 2f } //00 00  :/"&"/ik"&"at"&"em"&"ia.u"&"nt"&"ir"&"ta.a"&"c.i"&"d/a"&"s"&"se"&"ts/V"&"T/
	condition:
		any of ($a_*)
 
}