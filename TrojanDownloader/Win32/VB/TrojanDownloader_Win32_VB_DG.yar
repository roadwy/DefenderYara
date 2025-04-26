
rule TrojanDownloader_Win32_VB_DG{
	meta:
		description = "TrojanDownloader:Win32/VB.DG,SIGNATURE_TYPE_PEHSTR,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {41 64 6f 62 65 20 46 6c 61 73 68 20 50 6c 61 79 65 72 } //1 Adobe Flash Player
		$a_01_1 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } //1 URLDownloadToFileA
		$a_01_2 = {5c 00 4c 00 4f 00 41 00 44 00 45 00 52 00 5c 00 50 00 72 00 6f 00 6a 00 65 00 63 00 74 00 31 00 2e 00 76 00 62 00 70 00 } //1 \LOADER\Project1.vbp
		$a_01_3 = {2f 00 66 00 63 00 6b 00 65 00 64 00 69 00 74 00 6f 00 72 00 2f 00 } //1 /fckeditor/
		$a_01_4 = {45 00 73 00 74 00 65 00 20 00 61 00 70 00 6c 00 69 00 63 00 61 00 74 00 69 00 76 00 6f 00 } //1 Este aplicativo
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}