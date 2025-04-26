
rule TrojanDownloader_O97M_Powdow_RVBS_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.RVBS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {63 72 65 61 74 65 6f 62 6a 65 63 74 28 77 77 2b 73 2b 63 2b 72 2b 69 2b 70 2b 74 2b 64 64 2b 73 2b 68 2b 65 2b 6c 2b 6c 29 2e 72 75 6e 73 74 72 65 6e 64 73 75 62 } //1 createobject(ww+s+c+r+i+p+t+dd+s+h+e+l+l).runstrendsub
		$a_01_1 = {70 3d 22 70 22 6f 3d 22 6f 22 77 3d 22 77 22 65 3d 22 65 22 72 3d 22 72 22 73 3d 22 73 22 68 3d 22 68 22 6c 3d 22 6c 22 64 64 3d 22 2e 22 } //1 p="p"o="o"w="w"e="e"r="r"s="s"h="h"l="l"dd="."
		$a_01_2 = {61 75 74 6f 6f 70 65 6e 28 29 6c 6f 76 65 65 6e 64 73 75 62 } //1 autoopen()loveendsub
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
rule TrojanDownloader_O97M_Powdow_RVBS_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/Powdow.RVBS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {2e 22 44 4f 77 60 4e 4c 60 4f 61 64 73 60 54 52 49 60 4e 67 22 28 28 27 68 74 27 2b 27 74 70 73 27 2b 27 3a 2f 2f 70 61 73 74 65 62 69 6e 2e 63 6f 6d 2f 72 61 77 27 2b 27 2f 27 2b 27 57 4e 4a 27 2b 27 44 27 2b 27 35 58 27 2b 27 52 27 2b 27 76 27 29 29 } //1 ."DOw`NL`Oads`TRI`Ng"(('ht'+'tps'+'://pastebin.com/raw'+'/'+'WNJ'+'D'+'5X'+'R'+'v'))
		$a_01_1 = {3d 45 58 45 43 28 22 20 26 20 43 68 72 28 33 34 29 20 26 20 43 68 72 28 39 39 29 20 26 20 43 68 72 28 31 30 39 29 20 26 20 43 68 72 28 31 30 30 29 20 26 20 22 20 2f 63 20 70 6f 5e 77 5e 65 72 73 68 65 5e 6c 6c 20 43 3a 5c 70 72 6f 67 72 61 6d 64 61 74 61 5c 6b 68 6b 68 6b 68 2e 70 73 31 22 20 26 20 43 68 72 28 33 34 29 } //1 =EXEC(" & Chr(34) & Chr(99) & Chr(109) & Chr(100) & " /c po^w^ershe^ll C:\programdata\khkhkh.ps1" & Chr(34)
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}