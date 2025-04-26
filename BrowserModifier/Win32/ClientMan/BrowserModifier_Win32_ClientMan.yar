
rule BrowserModifier_Win32_ClientMan{
	meta:
		description = "BrowserModifier:Win32/ClientMan,SIGNATURE_TYPE_PEHSTR_EXT,09 00 06 00 04 00 00 "
		
	strings :
		$a_01_0 = {5c 57 61 6c 74 5c 6d 65 74 61 48 65 6c 70 65 72 5c 5f 49 45 42 72 6f 77 73 65 72 48 65 6c 70 65 72 2e 70 61 73 } //3 \Walt\metaHelper\_IEBrowserHelper.pas
		$a_01_1 = {6d 65 74 61 77 72 64 73 2e 6c 73 74 } //2 metawrds.lst
		$a_01_2 = {2f 67 61 56 32 2e 70 68 70 3f 76 65 72 3d } //3 /gaV2.php?ver=
		$a_01_3 = {65 78 70 6c 6f 72 65 72 5c 42 72 6f 77 73 65 72 20 48 65 6c 70 65 72 20 4f 62 6a 65 63 74 73 5c } //1 explorer\Browser Helper Objects\
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*2+(#a_01_2  & 1)*3+(#a_01_3  & 1)*1) >=6
 
}
rule BrowserModifier_Win32_ClientMan_2{
	meta:
		description = "BrowserModifier:Win32/ClientMan,SIGNATURE_TYPE_PEHSTR,0c 00 0c 00 0c 00 00 "
		
	strings :
		$a_01_0 = {2a 67 6f 6f 67 6c 65 2a 73 65 61 72 63 68 2a 71 3d } //1 *google*search*q=
		$a_01_1 = {2a 73 65 61 72 63 68 2e 79 61 68 6f 6f 2e 63 6f 6d } //1 *search.yahoo.com
		$a_01_2 = {2a 73 65 61 72 63 68 2e 6c 69 76 65 2e 63 6f 6d } //1 *search.live.com
		$a_01_3 = {2a 73 65 61 72 63 68 2e 6d 73 6e 2e 63 6f 6d } //1 *search.msn.com
		$a_01_4 = {37 32 2e 31 36 37 2e 35 32 2e 31 37 33 2f 3f } //1 72.167.52.173/?
		$a_01_5 = {53 65 72 76 65 72 54 72 61 6e 73 66 65 72 53 69 74 65 2e 63 6f 6d 2f 71 77 65 2e 74 78 74 } //1 ServerTransferSite.com/qwe.txt
		$a_01_6 = {42 72 6f 77 73 65 72 48 65 6c 70 65 72 31 2e 64 6c 6c } //1 BrowserHelper1.dll
		$a_01_7 = {41 44 57 41 52 45 32 5c 5f 49 45 42 72 6f 77 73 65 72 48 65 6c 70 65 72 2e 70 61 73 } //1 ADWARE2\_IEBrowserHelper.pas
		$a_01_8 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 65 78 70 6c 6f 72 65 72 5c 42 72 6f 77 73 65 72 20 48 65 6c 70 65 72 20 4f 62 6a 65 63 74 73 } //1 Software\Microsoft\Windows\CurrentVersion\explorer\Browser Helper Objects
		$a_01_9 = {47 65 74 43 6c 69 70 62 6f 61 72 64 44 61 74 61 } //1 GetClipboardData
		$a_01_10 = {49 6e 74 65 72 6e 65 74 4f 70 65 6e 55 72 6c 41 } //1 InternetOpenUrlA
		$a_01_11 = {48 74 74 70 51 75 65 72 79 49 6e 66 6f 41 } //1 HttpQueryInfoA
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1) >=12
 
}