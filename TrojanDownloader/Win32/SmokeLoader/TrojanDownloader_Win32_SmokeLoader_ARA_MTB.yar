
rule TrojanDownloader_Win32_SmokeLoader_ARA_MTB{
	meta:
		description = "TrojanDownloader:Win32/SmokeLoader.ARA!MTB,SIGNATURE_TYPE_PEHSTR,0a 00 0a 00 05 00 00 "
		
	strings :
		$a_01_0 = {78 00 75 00 74 00 61 00 73 00 65 00 62 00 6f 00 6e 00 69 00 77 00 69 00 6c 00 69 00 6b 00 69 00 76 00 6f 00 6c 00 6f 00 63 00 69 00 64 00 69 00 7a 00 61 00 77 00 69 00 6a 00 75 00 62 00 69 00 68 00 65 00 63 00 69 00 76 00 6f 00 6e 00 6f 00 64 00 } //2 xutaseboniwilikivolocidizawijubihecivonod
		$a_01_1 = {6d 00 6f 00 73 00 65 00 7a 00 6f 00 67 00 6f 00 6e 00 75 00 66 00 6f 00 7a 00 75 00 64 00 69 00 70 00 65 00 6a 00 61 00 73 00 65 00 64 00 6f 00 } //2 mosezogonufozudipejasedo
		$a_01_2 = {62 00 65 00 66 00 75 00 62 00 75 00 76 00 61 00 77 00 65 00 } //2 befubuvawe
		$a_01_3 = {75 00 7a 00 75 00 74 00 69 00 6a 00 61 00 67 00 6f 00 66 00 65 00 64 00 6f 00 66 00 75 00 70 00 } //2 uzutijagofedofup
		$a_01_4 = {72 00 75 00 7a 00 6f 00 78 00 6f 00 74 00 6f 00 7a 00 69 00 70 00 61 00 64 00 } //2 ruzoxotozipad
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2) >=10
 
}