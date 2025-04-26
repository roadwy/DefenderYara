
rule TrojanDownloader_Win32_Renos_gen_K{
	meta:
		description = "TrojanDownloader:Win32/Renos.gen!K,SIGNATURE_TYPE_PEHSTR_EXT,2f 00 2e 00 0b 00 00 "
		
	strings :
		$a_00_0 = {53 74 61 72 74 53 65 72 76 69 63 65 41 } //10 StartServiceA
		$a_00_1 = {43 72 65 61 74 65 50 72 6f 63 65 73 73 41 } //10 CreateProcessA
		$a_01_2 = {41 63 63 65 73 73 69 62 6c 65 4f 62 6a 65 63 74 46 72 6f 6d 57 69 6e 64 6f 77 } //10 AccessibleObjectFromWindow
		$a_01_3 = {49 6e 74 65 72 6e 65 74 4f 70 65 6e 41 } //10 InternetOpenA
		$a_01_4 = {77 69 6e 61 76 78 78 2e 65 78 65 } //1 winavxx.exe
		$a_01_5 = {7b 41 42 43 44 45 43 46 30 2d 34 42 31 35 2d 31 31 44 31 2d 41 42 45 44 2d 37 30 39 35 34 39 43 31 30 30 30 30 7d } //1 {ABCDECF0-4B15-11D1-ABED-709549C10000}
		$a_01_6 = {49 45 48 6c 70 72 4f 62 6a 2e 49 45 48 6c 70 72 4f 62 6a } //1 IEHlprObj.IEHlprObj
		$a_01_7 = {27 42 72 6f 77 73 65 72 20 48 65 6c 70 65 72 20 4f 62 6a 65 63 74 73 27 } //1 'Browser Helper Objects'
		$a_01_8 = {72 65 67 73 76 72 33 32 20 2f 73 20 76 74 72 2e 64 6c 6c } //1 regsvr32 /s vtr.dll
		$a_01_9 = {73 79 73 74 65 6d 73 2e 74 78 74 } //1 systems.txt
		$a_01_10 = {49 45 48 65 6c 70 65 72 2e 44 4c 4c } //1 IEHelper.DLL
	condition:
		((#a_00_0  & 1)*10+(#a_00_1  & 1)*10+(#a_01_2  & 1)*10+(#a_01_3  & 1)*10+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1) >=46
 
}