
rule TrojanDownloader_Win32_Zurgop_YT_MTB{
	meta:
		description = "TrojanDownloader:Win32/Zurgop.YT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_81_0 = {71 72 73 74 75 76 77 78 79 7a 65 69 6f 75 62 64 61 62 63 64 65 66 67 68 69 6a 6b 6c 6d 6e 6f 70 34 68 69 66 69 65 35 36 61 37 62 26 23 64 33 77 48 } //1 qrstuvwxyzeioubdabcdefghijklmnop4hifie56a7b&#d3wH
		$a_81_1 = {4c 6f 63 61 6c 5c 7b 43 31 35 37 33 30 45 32 2d 31 34 35 43 2d 34 63 35 65 2d 42 30 30 35 2d 33 42 43 37 35 33 46 34 32 34 37 35 7d 2d 6f 6e 63 65 2d 66 6c 61 67 } //1 Local\{C15730E2-145C-4c5e-B005-3BC753F42475}-once-flag
		$a_81_2 = {5c 72 65 73 6f 75 72 63 65 2d 61 2e 64 61 74 } //1 \resource-a.dat
		$a_81_3 = {68 74 74 70 3a 2f 2f } //1 http://
		$a_81_4 = {2f 73 65 61 72 63 68 2f 3f 71 3d } //1 /search/?q=
		$a_81_5 = {49 6e 74 65 72 6e 65 74 4f 70 65 6e 55 72 6c 41 } //1 InternetOpenUrlA
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=6
 
}