
rule TrojanDownloader_O97M_Emotet_ALY_MTB{
	meta:
		description = "TrojanDownloader:O97M/Emotet.ALY!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {5c 73 6f 61 6d 31 2e 64 6c 6c } //1 \soam1.dll
		$a_01_1 = {5c 73 6f 61 6d 32 2e 64 6c 6c } //1 \soam2.dll
		$a_01_2 = {5c 73 6f 61 6d 33 2e 64 6c 6c } //1 \soam3.dll
		$a_01_3 = {75 72 6c 6d 6f 6e } //1 urlmon
		$a_01_4 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } //1 URLDownloadToFileA
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}