
rule TrojanDownloader_O97M_Powdow_RVCL_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.RVCL!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {63 6d 64 2f 63 73 74 61 72 74 2f 6d 69 6e 70 6f 22 63 61 72 32 3d 22 77 65 72 73 68 65 6c 6c 2d 65 78 62 79 22 63 61 72 33 3d 22 70 61 73 73 2d 6e 6f 70 2d 77 68 3b 69 27 65 27 78 28 69 77 22 63 61 72 34 3d 22 72 28 27 68 74 74 70 73 3a 2f 2f } //1 cmd/cstart/minpo"car2="wershell-exby"car3="pass-nop-wh;i'e'x(iw"car4="r('https://
		$a_01_1 = {2f 66 63 38 66 31 39 62 32 66 36 38 65 30 39 62 30 39 66 31 63 36 39 61 66 30 36 36 66 66 64 36 66 65 32 63 64 32 30 63 61 2f 66 69 6c 65 73 2f 62 6c 61 63 6b 2d 73 74 61 72 74 2e 74 78 74 27 29 2d 75 73 65 62 29 3b 73 74 61 72 74 2d 73 6c 65 65 70 } //1 /fc8f19b2f68e09b09f1c69af066ffd6fe2cd20ca/files/black-start.txt')-useb);start-sleep
		$a_01_2 = {73 68 65 6c 6c 69 5f 6e 61 6d 65 65 6e 64 66 75 6e 63 74 69 6f 6e } //1 shelli_nameendfunction
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
rule TrojanDownloader_O97M_Powdow_RVCL_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/Powdow.RVCL!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {73 75 62 61 75 74 6f 5f 6f 70 65 6e 28 29 63 61 6c 6c 78 63 67 75 78 6c 76 66 65 6e 64 73 75 62 73 75 62 78 63 67 75 78 6c 76 66 28 29 64 69 6d 63 61 73 73 74 72 69 6e 67 63 3d 22 70 6f 77 65 72 73 68 65 6c 6c 2e 65 78 65 2d 6e 6f 70 2d 77 68 69 64 64 65 6e 2d 65 6e 63 6a 61 62 78 61 67 6b 61 62 67 61 7a 61 64 69 61 69 61 61 39 61 63 61 61 71 61 61 69 61 61 30 61 } //1 subauto_open()callxcguxlvfendsubsubxcguxlvf()dimcasstringc="powershell.exe-nop-whidden-encjabxagkabgazadiaiaa9acaaqaaiaa0a
		$a_01_1 = {61 67 67 61 64 61 62 30 61 68 61 61 63 77 61 36 61 63 38 61 6c 77 22 5f 26 22 61 78 61 64 6b 61 6e 61 61 75 61 64 65 61 6f 61 61 79 61 63 34 61 6d 71 61 32 61 64 71 61 6c 67 61 78 61 64 71 61 6f 71 61 36 61 64 67 61 6d 61 61 34 61 64 61 61 6c 77 62 6d 61 67 38 61 62 67 62 30 61 67 65 61 64 77 62 6c 61 68 6d 61 62 77 62 74 61 67 75 61 6c 67 62 33 61 67 38 61 7a 67 62 6d 61 63 69 61 6b 71 61 } //1 aggadab0ahaacwa6ac8alw"_&"axadkanaauadeaoaayac4amqa2adqalgaxadqaoqa6adgamaa4adaalwbmag8abgb0ageadwblahmabwbtagualgb3ag8azgbmaciakqa
		$a_01_2 = {22 73 68 65 6c 6c 28 63 29 65 6e 64 73 75 62 } //1 "shell(c)endsub
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}