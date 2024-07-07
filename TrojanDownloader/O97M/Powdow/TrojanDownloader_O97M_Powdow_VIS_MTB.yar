
rule TrojanDownloader_O97M_Powdow_VIS_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.VIS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {2b 27 6c 6f 61 64 46 69 6c 65 27 29 } //1 +'loadFile')
		$a_01_1 = {62 79 70 61 73 73 20 73 74 41 52 74 } //1 bypass stARt
		$a_01_2 = {74 74 70 73 3a 2f 2f 74 69 6e 79 75 72 6c 2e 63 6f 6d 2f 79 38 70 62 6f 77 6e 74 } //1 ttps://tinyurl.com/y8pbownt
		$a_01_3 = {44 65 73 74 69 6e 61 74 69 6f 6e 20 22 24 7b 65 6e 56 60 3a 61 70 70 64 61 74 61 7d } //1 Destination "${enV`:appdata}
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}
rule TrojanDownloader_O97M_Powdow_VIS_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/Powdow.VIS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 73 3a 2f 2f 63 75 74 74 2e 6c 79 2f 6a 6a 66 49 51 38 75 27 2c 27 70 64 } //1 https://cutt.ly/jjfIQ8u','pd
		$a_01_1 = {27 44 6f 77 6e 27 2b 27 6c 6f 61 64 46 69 6c 65 27 } //1 'Down'+'loadFile'
		$a_01_2 = {6f 77 65 72 73 68 65 5e 6c 5e 6c 20 2d 77 20 31 } //1 owershe^l^l -w 1
		$a_01_3 = {61 74 74 72 69 62 20 2b 73 20 2b 68 20 70 } //1 attrib +s +h p
		$a_01_4 = {62 61 74 27 29 2e 42 2e 6e 2e } //1 bat').B.n.
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}