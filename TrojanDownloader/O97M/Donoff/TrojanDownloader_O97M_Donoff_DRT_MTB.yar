
rule TrojanDownloader_O97M_Donoff_DRT_MTB{
	meta:
		description = "TrojanDownloader:O97M/Donoff.DRT!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {4d 69 64 28 22 69 5c 34 46 54 2d 4b 57 73 63 72 69 70 74 2e 53 68 65 6c 6c } //1 Mid("i\4FT-KWscript.Shell
		$a_01_1 = {4b 24 78 49 55 5c 38 38 33 38 2e 65 78 65 } //1 K$xIU\8838.exe
		$a_01_2 = {43 4c 6e 67 28 30 20 4f 72 20 36 29 2c 20 43 4c 6e 67 28 28 36 36 38 20 2b 20 2d 36 35 33 23 29 20 41 6e 64 20 39 29 29 } //1 CLng(0 Or 6), CLng((668 + -653#) And 9))
		$a_01_3 = {43 54 54 76 56 2c 62 22 2c 20 22 22 } //1 CTTvV,b", ""
		$a_01_4 = {70 61 72 6f 63 68 69 61 6c 6c 79 77 61 72 74 } //1 parochiallywart
		$a_01_5 = {57 70 45 68 74 42 41 74 66 31 2e 70 68 70 } //1 WpEhtBAtf1.php
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}
rule TrojanDownloader_O97M_Donoff_DRT_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/Donoff.DRT!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {63 61 72 69 6e 74 65 72 66 61 63 65 5f 6e 61 6d 65 } //1 carinterface_name
		$a_01_1 = {45 72 72 6f 72 31 2e 49 6d 61 67 65 37 37 38 38 31 31 31 2e 54 61 67 } //1 Error1.Image7788111.Tag
		$a_01_2 = {45 72 72 6f 72 31 2e 49 6d 61 67 65 37 37 38 38 31 31 32 2e 43 6f 6e 74 72 6f 6c 54 69 70 54 65 78 74 } //1 Error1.Image7788112.ControlTipText
		$a_01_3 = {6b 61 6d 61 74 65 72 61 20 2b 20 22 20 22 20 2b 20 4d 61 6e 68 6f 6f 73 20 2b 20 6d 65 72 61 77 61 20 2b 20 74 65 72 68 6f 77 61 } //1 kamatera + " " + Manhoos + merawa + terhowa
		$a_01_4 = {53 68 65 6c 6c 20 69 5f 6e 61 6d 65 } //1 Shell i_name
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}