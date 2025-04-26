
rule TrojanDownloader_Win32_Agent_ZH{
	meta:
		description = "TrojanDownloader:Win32/Agent.ZH,SIGNATURE_TYPE_PEHSTR_EXT,ffffff95 00 ffffff95 00 0d 00 00 "
		
	strings :
		$a_00_0 = {25 73 3d 25 73 0d 0a 00 4e 55 4c 00 } //100
		$a_01_1 = {5b 72 65 6e 61 6d 65 5d } //5 [rename]
		$a_01_2 = {77 69 6e 69 6e 69 74 2e } //5 wininit.
		$a_01_3 = {5c 75 73 72 69 6e 69 74 2e 64 6c 6c } //5 \usrinit.dll
		$a_01_4 = {7b 35 42 30 32 45 42 41 31 2d 45 46 44 44 2d 34 37 37 44 2d 41 33 37 46 2d 30 35 33 38 33 31 36 35 43 39 43 30 7d } //5 {5B02EBA1-EFDD-477D-A37F-05383165C9C0}
		$a_00_5 = {5a 77 4f 70 65 6e 53 65 63 74 69 6f 6e } //5 ZwOpenSection
		$a_01_6 = {49 6e 74 65 72 6e 65 74 52 65 61 64 46 69 6c 65 } //5 InternetReadFile
		$a_00_7 = {53 68 65 6c 6c 45 78 65 63 75 74 65 41 } //5 ShellExecuteA
		$a_01_8 = {4d 61 70 56 69 65 77 4f 66 46 69 6c 65 } //5 MapViewOfFile
		$a_01_9 = {72 65 67 73 76 72 33 32 } //5 regsvr32
		$a_01_10 = {68 74 74 70 3a 2f 2f 77 77 77 2e 61 6c 78 75 70 2e 63 6f 6d 2f 62 69 6e 2f 55 70 2e 69 6e 69 } //2 http://www.alxup.com/bin/Up.ini
		$a_01_11 = {5c 55 70 41 75 74 6f 2e 69 6e 69 } //1 \UpAuto.ini
		$a_01_12 = {41 75 74 6f 55 70 2e 65 78 65 } //1 AutoUp.exe
	condition:
		((#a_00_0  & 1)*100+(#a_01_1  & 1)*5+(#a_01_2  & 1)*5+(#a_01_3  & 1)*5+(#a_01_4  & 1)*5+(#a_00_5  & 1)*5+(#a_01_6  & 1)*5+(#a_00_7  & 1)*5+(#a_01_8  & 1)*5+(#a_01_9  & 1)*5+(#a_01_10  & 1)*2+(#a_01_11  & 1)*1+(#a_01_12  & 1)*1) >=149
 
}