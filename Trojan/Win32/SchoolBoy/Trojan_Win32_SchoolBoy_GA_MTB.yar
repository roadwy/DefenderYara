
rule Trojan_Win32_SchoolBoy_GA_MTB{
	meta:
		description = "Trojan:Win32/SchoolBoy.GA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,12 00 12 00 0e 00 00 "
		
	strings :
		$a_01_0 = {63 6d 64 20 2f 63 20 74 31 30 33 36 5f 74 65 73 74 2e 62 61 74 } //3 cmd /c t1036_test.bat
		$a_01_1 = {54 65 73 74 5f 54 31 30 33 36 } //1 Test_T1036
		$a_01_2 = {52 55 4e 50 52 4f 47 52 41 4d } //1 RUNPROGRAM
		$a_01_3 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e 4f 6e 63 65 } //3 Software\Microsoft\Windows\CurrentVersion\RunOnce
		$a_01_4 = {50 4f 53 54 52 55 4e 50 52 4f 47 52 41 4d } //1 POSTRUNPROGRAM
		$a_01_5 = {44 65 6c 4e 6f 64 65 52 75 6e 44 4c 4c 33 32 } //1 DelNodeRunDLL32
		$a_01_6 = {44 65 63 72 79 70 74 46 69 6c 65 41 } //1 DecryptFileA
		$a_01_7 = {53 48 4f 57 57 49 4e 44 4f 57 } //1 SHOWWINDOW
		$a_01_8 = {46 49 4e 49 53 48 4d 53 47 } //1 FINISHMSG
		$a_01_9 = {6d 73 64 6f 77 6e 6c 64 2e 74 6d 70 } //1 msdownld.tmp
		$a_01_10 = {54 4d 50 34 33 35 31 24 2e 54 4d 50 } //1 TMP4351$.TMP
		$a_01_11 = {53 65 74 57 69 6e 64 6f 77 54 65 78 74 41 } //1 SetWindowTextA
		$a_01_12 = {54 31 30 33 36 5f 7e 31 2e 42 41 54 } //1 T1036_~1.BAT
		$a_00_13 = {54 00 65 00 6d 00 70 00 6f 00 72 00 61 00 72 00 79 00 20 00 66 00 6f 00 6c 00 64 00 65 00 72 00 } //1 Temporary folder
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*3+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1+(#a_01_12  & 1)*1+(#a_00_13  & 1)*1) >=18
 
}