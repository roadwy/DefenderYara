
rule Worm_Win32_Lashplay_gen_A{
	meta:
		description = "Worm:Win32/Lashplay.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 10 00 00 "
		
	strings :
		$a_00_0 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 65 78 70 6c 6f 72 65 72 5c 42 72 6f 77 73 65 72 20 48 65 6c 70 65 72 20 4f 62 6a 65 63 74 73 5c } //1 Software\Microsoft\Windows\CurrentVersion\explorer\Browser Helper Objects\
		$a_00_1 = {68 74 74 70 3a 2f 2f 6c 69 6e 67 2e 70 63 33 37 2e 63 6f 6d 2f 66 6c 61 73 68 70 6c 61 79 2e 64 6c 6c } //1 http://ling.pc37.com/flashplay.dll
		$a_00_2 = {68 74 74 70 3a 2f 2f 77 77 77 2e 39 36 31 36 33 2e 63 6e 2f 64 6f 77 6e 2f } //1 http://www.96163.cn/down/
		$a_00_3 = {5c 66 6c 61 73 68 70 6c 61 79 2e 64 6c 6c } //1 \flashplay.dll
		$a_00_4 = {62 61 69 64 75 } //1 baidu
		$a_00_5 = {65 78 70 6c 6f 72 65 72 62 61 72 } //1 explorerbar
		$a_00_6 = {5c 6d 73 5f 73 74 61 72 74 2e 65 78 65 } //1 \ms_start.exe
		$a_00_7 = {3a 5c 61 75 74 6f 72 75 6e 2e 69 6e 66 } //1 :\autorun.inf
		$a_00_8 = {2e 65 78 65 20 61 75 74 6f 72 75 6e } //1 .exe autorun
		$a_00_9 = {49 79 61 6f 64 69 61 6e 67 65 } //1 Iyaodiange
		$a_00_10 = {73 68 6a 5f 70 6c 61 79 2e 68 74 6d } //1 shj_play.htm
		$a_00_11 = {7a 68 65 6e 67 75 6f 79 69 6e } //1 zhenguoyin
		$a_02_12 = {5c 24 24 66 6c 61 73 [0-01] 68 70 24 24 2e 62 61 74 } //1
		$a_00_13 = {5c 77 69 6e 5f 2a } //1 \win_*
		$a_00_14 = {3a 33 37 2f 70 63 33 37 2f } //1 :37/pc37/
		$a_00_15 = {72 65 6e 61 6d 65 20 66 6c 61 73 68 70 6c 61 79 2e 64 6c 6c 20 66 6c 61 73 68 70 6c 61 79 2e 64 6c 6c 5f } //1 rename flashplay.dll flashplay.dll_
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1+(#a_00_8  & 1)*1+(#a_00_9  & 1)*1+(#a_00_10  & 1)*1+(#a_00_11  & 1)*1+(#a_02_12  & 1)*1+(#a_00_13  & 1)*1+(#a_00_14  & 1)*1+(#a_00_15  & 1)*1) >=8
 
}