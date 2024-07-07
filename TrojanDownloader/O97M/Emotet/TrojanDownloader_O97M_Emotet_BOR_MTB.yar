
rule TrojanDownloader_O97M_Emotet_BOR_MTB{
	meta:
		description = "TrojanDownloader:O97M/Emotet.BOR!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_03_0 = {53 79 73 57 6f 77 36 34 5c 90 02 15 5c 57 69 6e 64 6f 77 73 5c 90 02 15 2c 30 2c 30 29 90 00 } //1
		$a_01_1 = {44 22 26 22 6c 22 26 22 6c 52 22 26 22 65 22 26 22 67 69 73 74 65 72 22 26 22 53 65 72 76 65 22 26 22 72 } //1 D"&"l"&"lR"&"e"&"gister"&"Serve"&"r
		$a_01_2 = {44 22 26 22 6c 22 26 22 6c 52 22 26 22 65 67 69 73 74 65 72 22 26 22 53 65 72 76 65 22 26 22 72 } //1 D"&"l"&"lR"&"egister"&"Serve"&"r
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=2
 
}