
rule Backdoor_Win32_DialXLite{
	meta:
		description = "Backdoor:Win32/DialXLite,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0c 00 00 "
		
	strings :
		$a_01_0 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 45 78 70 6c 6f 72 65 72 5c 52 65 63 65 6e 74 44 6f 63 73 } //1 Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs
		$a_01_1 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 45 78 70 6c 6f 72 65 72 5c 52 75 6e 4d 52 55 } //1 Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
		$a_01_2 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c 54 79 70 65 64 55 52 4c 73 } //1 Software\Microsoft\Internet Explorer\TypedURLs
		$a_01_3 = {44 49 41 4c 58 4c 49 54 45 2d } //5 DIALXLITE-
		$a_01_4 = {63 61 70 69 00 00 00 00 69 6e 74 65 72 6e 65 74 00 00 00 00 70 70 70 00 45 74 68 65 72 6e 65 74 00 00 00 00 44 53 4c 00 69 73 64 6e 00 00 00 00 6d 6f 64 65 6d } //3
		$a_01_5 = {62 65 72 73 65 6e 74 65 72 2e 63 67 69 } //2 bersenter.cgi
		$a_00_6 = {2f 63 20 43 3a 5c 65 78 65 2e 65 78 65 } //2 /c C:\exe.exe
		$a_01_7 = {68 74 74 70 3a 2f 2f 77 77 77 2e 64 69 61 6c 65 72 63 6c 75 62 2e 63 6f 6d } //3 http://www.dialerclub.com
		$a_01_8 = {30 39 30 39 30 32 34 30 30 39 34 } //3 09090240094
		$a_01_9 = {30 39 30 39 39 36 35 33 31 32 31 } //3 09099653121
		$a_01_10 = {31 2d 32 2d 33 2d 43 4f 4f 4b } //3 1-2-3-COOK
		$a_01_11 = {42 65 73 74 20 50 6f 72 6e 6f 20 4e 65 74 7a 77 65 72 6b } //6 Best Porno Netzwerk
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*5+(#a_01_4  & 1)*3+(#a_01_5  & 1)*2+(#a_00_6  & 1)*2+(#a_01_7  & 1)*3+(#a_01_8  & 1)*3+(#a_01_9  & 1)*3+(#a_01_10  & 1)*3+(#a_01_11  & 1)*6) >=10
 
}