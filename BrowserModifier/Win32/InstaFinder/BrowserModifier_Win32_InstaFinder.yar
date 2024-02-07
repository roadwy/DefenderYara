
rule BrowserModifier_Win32_InstaFinder{
	meta:
		description = "BrowserModifier:Win32/InstaFinder,SIGNATURE_TYPE_PEHSTR,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {64 6f 77 6e 6c 6f 61 64 2e 69 6e 73 74 61 66 69 6e 64 65 72 2e 63 6f 6d } //01 00  download.instafinder.com
		$a_01_1 = {69 6e 73 74 61 66 69 6e 64 65 72 5f 69 6e 73 74 61 6c 6c 66 75 6c 6c 2e 65 78 65 } //01 00  instafinder_installfull.exe
		$a_01_2 = {49 00 6e 00 73 00 74 00 61 00 66 00 69 00 6e 00 64 00 65 00 72 00 20 00 4c 00 4c 00 43 00 } //01 00  Instafinder LLC
		$a_01_3 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //01 00  Software\Microsoft\Windows\CurrentVersion\Run
		$a_01_4 = {48 74 74 70 51 75 65 72 79 49 6e 66 6f 41 } //01 00  HttpQueryInfoA
		$a_01_5 = {49 6e 74 65 72 6e 65 74 4f 70 65 6e 55 72 6c 41 } //00 00  InternetOpenUrlA
	condition:
		any of ($a_*)
 
}