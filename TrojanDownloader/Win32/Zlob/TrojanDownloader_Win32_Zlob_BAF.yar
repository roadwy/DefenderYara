
rule TrojanDownloader_Win32_Zlob_BAF{
	meta:
		description = "TrojanDownloader:Win32/Zlob.BAF,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 0f 00 00 "
		
	strings :
		$a_01_0 = {25 73 2f 74 65 73 74 2f 3f 63 3d 25 31 2e 31 64 25 64 25 31 2e 31 64 } //3 %s/test/?c=%1.1d%d%1.1d
		$a_01_1 = {25 73 2f 64 6f 63 2e 70 68 70 3f 74 79 70 65 3d 66 69 6c 65 } //3 %s/doc.php?type=file
		$a_01_2 = {5f 53 54 41 52 54 45 44 5f } //2 _STARTED_
		$a_01_3 = {25 64 2e 62 61 74 } //2 %d.bat
		$a_01_4 = {5c 6d 79 76 2e 69 63 6f } //2 \myv.ico
		$a_01_5 = {75 73 65 72 5f 70 72 65 66 28 22 62 72 6f 77 73 65 72 2e 73 65 61 72 63 68 2e 73 65 6c 65 63 74 65 64 45 6e 67 69 6e 65 22 2c 20 22 53 65 61 72 63 68 22 29 2c } //2 user_pref("browser.search.selectedEngine", "Search"),
		$a_01_6 = {25 73 5c 53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 49 6e 74 65 72 6e 65 74 20 53 65 74 74 69 6e 67 73 5c 5a 6f 6e 65 4d 61 70 5c 52 61 6e 67 65 73 5c 52 61 6e 67 65 25 64 } //2 %s\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\Ranges\Range%d
		$a_01_7 = {73 63 61 6e 6e 65 72 2e 70 6f 77 65 72 61 6e 74 69 76 69 72 75 73 2d 32 30 30 39 2e 63 6f 6d } //1 scanner.powerantivirus-2009.com
		$a_01_8 = {69 65 61 6e 74 69 76 69 72 75 73 2e 63 6f 6d } //1 ieantivirus.com
		$a_01_9 = {6f 6e 6c 69 6e 65 76 69 64 65 6f 73 6f 66 74 65 78 2e 63 6f 6d } //1 onlinevideosoftex.com
		$a_01_10 = {63 6f 64 65 63 68 6f 73 74 2e 63 6f 6d } //1 codechost.com
		$a_01_11 = {32 31 36 2e 32 33 39 2e 2a 2e 2a } //1 216.239.*.*
		$a_01_12 = {32 30 35 2e 31 38 38 2e 2a 2e 2a } //1 205.188.*.*
		$a_01_13 = {37 37 2e 39 32 2e 38 38 2e 2a } //1 77.92.88.*
		$a_01_14 = {39 31 2e 32 30 33 2e 37 30 2e 2a } //1 91.203.70.*
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*3+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2+(#a_01_5  & 1)*2+(#a_01_6  & 1)*2+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1+(#a_01_12  & 1)*1+(#a_01_13  & 1)*1+(#a_01_14  & 1)*1) >=15
 
}