
rule TrojanDownloader_O97M_Powdow_ART_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.ART!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {28 6e 45 77 2d 6f 42 60 6a 65 63 54 20 4e 65 74 2e 57 65 62 63 4c 60 49 45 4e 74 29 } //1 (nEw-oB`jecT Net.WebcL`IENt)
		$a_01_1 = {2b 27 6c 6f 61 64 46 69 6c 65 27 29 } //1 +'loadFile')
		$a_01_2 = {74 74 70 73 3a 2f 2f 74 69 6e 79 75 72 6c 2e 63 6f 6d 2f 79 36 66 70 76 33 6c 6a } //1 ttps://tinyurl.com/y6fpv3lj
		$a_01_3 = {2d 44 65 73 74 69 6e 61 74 69 6f 6e 20 22 24 7b 65 6e 56 60 3a 74 65 6d 70 7d } //1 -Destination "${enV`:temp}
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}