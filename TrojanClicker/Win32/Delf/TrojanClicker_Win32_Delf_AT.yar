
rule TrojanClicker_Win32_Delf_AT{
	meta:
		description = "TrojanClicker:Win32/Delf.AT,SIGNATURE_TYPE_PEHSTR_EXT,ffffff82 00 ffffff82 00 0b 00 00 "
		
	strings :
		$a_01_0 = {53 4f 46 54 57 41 52 45 5c 42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 5c 52 54 4c } //10 SOFTWARE\Borland\Delphi\RTL
		$a_01_1 = {49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5f 54 72 69 64 65 6e 74 44 6c 67 46 72 61 6d 65 } //10 Internet Explorer_TridentDlgFrame
		$a_01_2 = {57 65 62 42 72 6f 77 73 65 72 31 53 74 61 74 75 73 54 65 78 74 43 68 61 6e 67 65 } //10 WebBrowser1StatusTextChange
		$a_01_3 = {54 57 65 62 42 72 6f 77 73 65 72 4f 6e 4d 65 6e 75 42 61 72 } //10 TWebBrowserOnMenuBar
		$a_01_4 = {54 50 72 6f 63 65 73 73 55 72 6c 41 63 74 69 6f 6e 45 76 65 6e 74 } //10 TProcessUrlActionEvent
		$a_01_5 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //10 Software\Microsoft\Windows\CurrentVersion\Run
		$a_01_6 = {55 73 65 72 20 41 67 65 6e 74 5c 50 6f 73 74 20 50 6c 61 74 66 6f 72 6d } //10 User Agent\Post Platform
		$a_01_7 = {68 74 6d 6c 66 69 6c 65 5c 73 68 65 6c 6c 5c 6f 70 65 6e 5c 64 64 65 65 78 65 63 5c 61 70 70 6c 69 63 61 74 69 6f 6e } //10 htmlfile\shell\open\ddeexec\application
		$a_01_8 = {48 6f 6e 62 65 66 6f 72 65 75 6e 6c 6f 61 64 } //10 Honbeforeunload
		$a_01_9 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 32 00 30 00 30 00 35 00 2d 00 73 00 65 00 61 00 72 00 63 00 68 00 2e 00 63 00 6f 00 6d 00 2f 00 67 00 6f 00 2f 00 67 00 6f 00 2e 00 70 00 68 00 70 00 } //30 http://2005-search.com/go/go.php
		$a_01_10 = {57 00 65 00 62 00 42 00 72 00 6f 00 77 00 73 00 65 00 72 00 31 00 2e 00 4c 00 6f 00 63 00 61 00 74 00 69 00 6f 00 6e 00 55 00 52 00 4c 00 } //10 WebBrowser1.LocationURL
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*10+(#a_01_3  & 1)*10+(#a_01_4  & 1)*10+(#a_01_5  & 1)*10+(#a_01_6  & 1)*10+(#a_01_7  & 1)*10+(#a_01_8  & 1)*10+(#a_01_9  & 1)*30+(#a_01_10  & 1)*10) >=130
 
}