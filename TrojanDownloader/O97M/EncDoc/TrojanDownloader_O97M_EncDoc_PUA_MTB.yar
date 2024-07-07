
rule TrojanDownloader_O97M_EncDoc_PUA_MTB{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.PUA!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {68 74 74 70 3a 2f 2f 67 72 61 66 66 69 74 69 77 6f 72 6b 73 68 6f 70 2e 73 65 2f 6c 69 76 6d 6d 62 2f 38 38 38 38 38 38 38 2e 70 6e 67 } //1 http://graffitiworkshop.se/livmmb/8888888.png
		$a_00_1 = {43 3a 5c 50 72 6f 67 72 61 6d 64 61 74 61 5c 47 6f 6c 61 73 44 68 } //1 C:\Programdata\GolasDh
		$a_00_2 = {64 54 6f 46 69 6c 65 41 } //1 dToFileA
		$a_00_3 = {46 69 6c 65 50 72 6f 74 6f } //1 FileProto
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}