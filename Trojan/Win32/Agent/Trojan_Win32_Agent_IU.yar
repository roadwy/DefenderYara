
rule Trojan_Win32_Agent_IU{
	meta:
		description = "Trojan:Win32/Agent.IU,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 0c 00 00 01 00 "
		
	strings :
		$a_00_0 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 45 78 70 6c 6f 72 65 72 5c 53 68 65 6c 6c 20 46 6f 6c 64 65 72 73 } //01 00  Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders
		$a_00_1 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c 4d 61 69 6e } //01 00  Software\Microsoft\Internet Explorer\Main
		$a_01_2 = {5c 4d 69 63 72 6f 73 6f 66 74 5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c 51 75 69 63 6b 20 4c 61 75 6e 63 68 } //01 00  \Microsoft\Internet Explorer\Quick Launch
		$a_00_3 = {5b 49 6e 74 65 72 6e 65 74 53 68 6f 72 74 63 75 74 5d } //01 00  [InternetShortcut]
		$a_01_4 = {49 6e 74 65 72 6e 65 74 52 65 61 64 46 69 6c 65 } //01 00  InternetReadFile
		$a_01_5 = {49 6e 74 65 72 6e 65 74 4f 70 65 6e 55 72 6c 41 } //01 00  InternetOpenUrlA
		$a_00_6 = {53 74 61 72 74 20 50 61 67 65 } //01 00  Start Page
		$a_01_7 = {48 54 54 50 54 45 53 54 } //01 00  HTTPTEST
		$a_01_8 = {68 6f 6d 65 75 72 6c } //01 00  homeurl
		$a_01_9 = {67 61 70 74 69 6d 65 } //01 00  gaptime
		$a_01_10 = {68 6f 6d 65 64 65 73 63 } //01 00  homedesc
		$a_01_11 = {69 63 6f 6e 75 72 6c } //00 00  iconurl
	condition:
		any of ($a_*)
 
}