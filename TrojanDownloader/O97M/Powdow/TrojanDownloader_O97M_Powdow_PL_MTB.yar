
rule TrojanDownloader_O97M_Powdow_PL_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.PL!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,0a 00 0a 00 0a 00 00 "
		
	strings :
		$a_02_0 = {74 74 70 73 3a 2f 2f 74 69 6e 79 75 72 6c 2e 63 6f 6d 2f 90 02 0a 27 2c 27 90 00 } //1
		$a_00_1 = {2d 77 20 31 20 28 6e 45 77 2d 6f 42 60 6a 65 63 54 20 4e 65 74 } //1 -w 1 (nEw-oB`jecT Net
		$a_00_2 = {57 65 62 63 4c 60 49 45 4e 74 29 } //1 WebcL`IENt)
		$a_00_3 = {6e 27 2b 27 6c 6f 61 64 46 69 6c 65 27 29 } //1 n'+'loadFile')
		$a_00_4 = {2d 77 20 31 20 2d 45 50 20 62 79 70 61 73 73 20 73 74 41 52 74 60 2d 73 6c 45 60 45 70 20 32 35 3b } //1 -w 1 -EP bypass stARt`-slE`Ep 25;
		$a_00_5 = {63 64 20 24 7b 65 6e 56 60 3a 61 70 70 64 61 74 61 7d 3b } //1 cd ${enV`:appdata};
		$a_00_6 = {64 61 64 61 64 61 64 61 66 61 66 61 66 61 66 61 } //1 dadadadafafafafa
		$a_00_7 = {75 73 65 6c 65 73 73 20 63 65 6c 6c } //1 useless cell
		$a_00_8 = {6d 61 67 69 63 20 63 65 6c 6c } //1 magic cell
		$a_00_9 = {65 70 69 63 20 63 65 6c 6c } //1 epic cell
	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1+(#a_00_8  & 1)*1+(#a_00_9  & 1)*1) >=10
 
}