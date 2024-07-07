
rule TrojanDownloader_O97M_EncDoc_PAR_MTB{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.PAR!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {76 62 61 2e 73 68 65 6c 6c 28 71 6a 6e 61 36 7a 71 67 7a 2b 6a 71 79 74 6b 33 65 36 62 2b 73 71 6d 62 61 6a 6b 6c 6e 29 29 65 6e 64 73 75 62 70 } //1 vba.shell(qjna6zqgz+jqytk3e6b+sqmbajkln))endsubp
		$a_01_1 = {31 74 6f 6c 65 6e 28 62 69 61 6b 7a 77 75 6f 76 29 73 74 65 70 32 67 6f 74 6f } //1 1tolen(biakzwuov)step2goto
		$a_01_2 = {26 63 68 72 24 28 76 61 6c 28 22 26 68 22 26 6d 69 64 24 28 62 69 61 6b 7a 77 75 6f 76 2c 70 74 31 6d 30 77 6f 77 67 2c 32 29 29 29 67 6f 74 6f 77 } //1 &chr$(val("&h"&mid$(biakzwuov,pt1m0wowg,2)))gotow
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}