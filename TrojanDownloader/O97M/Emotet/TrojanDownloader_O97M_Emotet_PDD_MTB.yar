
rule TrojanDownloader_O97M_Emotet_PDD_MTB{
	meta:
		description = "TrojanDownloader:O97M/Emotet.PDD!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 04 00 00 "
		
	strings :
		$a_01_0 = {3a 2f 2f 64 61 6c 67 61 68 61 76 75 7a 75 2e 63 6f 6d 2f 70 77 6b 66 6b 79 2f 4c 46 30 57 55 2f } //1 ://dalgahavuzu.com/pwkfky/LF0WU/
		$a_01_1 = {3a 2f 2f 64 6f 6c 70 68 69 6e 73 75 70 72 65 6d 65 68 61 76 75 7a 72 6f 62 6f 74 75 2e 63 6f 6d 2f 79 72 72 63 74 2f 51 63 62 78 68 71 43 51 2f } //1 ://dolphinsupremehavuzrobotu.com/yrrct/QcbxhqCQ/
		$a_01_2 = {3a 2f 2f 73 61 6e 64 69 65 67 6f 69 6e 73 75 72 61 6e 63 65 61 67 65 6e 74 73 2e 63 6f 6d 2f 63 67 69 2d 62 69 6e 2f 58 4b 31 56 53 58 5a 64 64 4c 64 4e 2f } //1 ://sandiegoinsuranceagents.com/cgi-bin/XK1VSXZddLdN/
		$a_01_3 = {3a 2f 2f 6b 69 6e 65 74 65 6b 74 75 72 6b 2e 63 6f 6d 2f 65 32 65 61 36 39 70 2f 39 55 35 32 4f 37 6a 54 6f 62 46 38 4a 2f } //1 ://kinetekturk.com/e2ea69p/9U52O7jTobF8J/
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=1
 
}