
rule TrojanDownloader_O97M_Powdow_PDOA_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.PDOA!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {29 74 68 67 3d 22 27 68 74 74 70 3a 2f 2f 65 6d 70 69 72 65 76 69 73 69 6f 6e 69 6e 63 2e 78 79 7a 2f 63 61 6c 2f 6d 65 64 69 61 2e 65 78 65 27 22 65 78 3d 22 6d 65 64 69 61 2e 65 78 65 27 3b 22 67 67 67 67 3d 22 28 28 } //1 )thg="'http://empirevisioninc.xyz/cal/media.exe'"ex="media.exe';"gggg="((
		$a_01_1 = {29 74 68 67 3d 22 27 68 74 74 70 3a 2f 2f 65 6d 70 69 72 65 76 69 73 69 6f 6e 69 6e 63 2e 78 79 7a 2f 63 61 6c 2f 77 6f 72 64 70 61 64 2e 65 78 65 27 22 65 78 3d 22 6d 65 64 69 61 2e 65 78 65 27 3b 22 67 67 67 67 3d 22 28 28 } //1 )thg="'http://empirevisioninc.xyz/cal/wordpad.exe'"ex="media.exe';"gggg="((
		$a_01_2 = {68 65 6c 6c 68 68 68 68 2b 28 22 22 2b 73 73 73 73 2b 67 67 67 67 2b 22 3b 69 6e 76 6f 6b 65 2d 69 74 65 6d 24 6d 6d 6d 6d 6d 6d 22 29 65 6e 64 73 75 62 } //1 hellhhhh+(""+ssss+gggg+";invoke-item$mmmmmm")endsub
		$a_01_3 = {2b 27 5c 61 70 70 64 61 74 61 5c 22 2b 65 78 73 73 73 73 3d 72 65 70 6c 61 63 65 28 73 73 73 73 2c } //1 +'\appdata\"+exssss=replace(ssss,
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}