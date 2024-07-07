
rule TrojanDownloader_O97M_EncDoc_HLO_MTB{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.HLO!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 3a 2f 2f 75 34 70 39 77 6f 34 6b 67 79 62 6f 2e 74 6f 70 2f 34 7a 34 76 50 4b 4e 45 68 48 2f 4a 5a 48 6a 47 47 2e 74 72 69 75 6d 70 68 6c 6f 61 64 65 72 } //1 http://u4p9wo4kgybo.top/4z4vPKNEhH/JZHjGG.triumphloader
		$a_01_1 = {7a 69 70 66 6c 64 72 } //1 zipfldr
		$a_01_2 = {43 72 65 61 74 65 44 69 72 65 63 74 6f 72 79 41 } //1 CreateDirectoryA
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}