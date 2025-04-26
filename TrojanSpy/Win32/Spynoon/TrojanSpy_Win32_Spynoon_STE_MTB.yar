
rule TrojanSpy_Win32_Spynoon_STE_MTB{
	meta:
		description = "TrojanSpy:Win32/Spynoon.STE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 09 00 00 "
		
	strings :
		$a_01_0 = {72 6f 72 79 68 63 72 6c 66 77 63 67 6e } //1 roryhcrlfwcgn
		$a_01_1 = {6f 6e 7a 73 62 74 6d 74 63 75 69 6b 71 } //1 onzsbtmtcuikq
		$a_01_2 = {65 65 74 78 67 62 6b 65 64 72 75 67 } //1 eetxgbkedrug
		$a_01_3 = {6a 6c 61 69 67 6a 6b 61 6b 78 66 75 66 73 } //1 jlaigjkakxfufs
		$a_01_4 = {78 71 75 74 67 69 67 62 68 73 70 61 } //1 xqutgigbhspa
		$a_01_5 = {25 41 50 50 44 41 54 41 25 } //1 %APPDATA%
		$a_01_6 = {79 62 6d 70 63 63 71 72 78 68 79 74 68 } //1 ybmpccqrxhyth
		$a_01_7 = {78 63 74 6e 74 78 6a 78 6b 7a } //1 xctntxjxkz
		$a_01_8 = {71 6e 65 71 63 76 67 66 79 75 78 } //1 qneqcvgfyux
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1) >=8
 
}