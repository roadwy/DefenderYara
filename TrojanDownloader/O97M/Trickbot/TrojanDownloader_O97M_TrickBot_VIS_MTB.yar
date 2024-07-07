
rule TrojanDownloader_O97M_TrickBot_VIS_MTB{
	meta:
		description = "TrojanDownloader:O97M/TrickBot.VIS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {44 6f 77 6e 6c 6f 61 64 46 69 6c 65 } //1 DownloadFile
		$a_01_1 = {68 69 70 65 72 64 6f 73 63 6f 6c 63 68 6f 65 73 2e 63 6f 6d 2f 64 65 6d 6f 69 6d 67 2e 67 69 66 } //1 hiperdoscolchoes.com/demoimg.gif
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}