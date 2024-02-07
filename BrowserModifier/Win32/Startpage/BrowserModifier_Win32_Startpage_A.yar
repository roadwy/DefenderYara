
rule BrowserModifier_Win32_Startpage_A{
	meta:
		description = "BrowserModifier:Win32/Startpage.A,SIGNATURE_TYPE_PEHSTR,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 49 00 6e 00 74 00 65 00 72 00 6e 00 65 00 74 00 20 00 45 00 78 00 70 00 6c 00 6f 00 72 00 65 00 72 00 5c 00 4d 00 61 00 69 00 6e 00 } //01 00  Software\Microsoft\Internet Explorer\Main
		$a_01_1 = {53 00 74 00 61 00 72 00 74 00 20 00 50 00 61 00 67 00 65 00 } //01 00  Start Page
		$a_01_2 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 77 00 77 00 77 00 2e 00 74 00 61 00 6b 00 74 00 75 00 6b 00 2e 00 74 00 6b 00 } //01 00  http://www.taktuk.tk
		$a_01_3 = {53 00 4f 00 46 00 54 00 57 00 41 00 52 00 45 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 5c 00 52 00 75 00 6e 00 } //01 00  SOFTWARE\Microsoft\Windows\CurrentVersion\Run
		$a_01_4 = {76 00 69 00 72 00 75 00 73 00 20 00 74 00 6f 00 74 00 61 00 6c 00 } //01 00  virus total
		$a_01_5 = {70 00 72 00 6f 00 6a 00 65 00 63 00 74 00 2e 00 65 00 78 00 65 00 } //00 00  project.exe
	condition:
		any of ($a_*)
 
}