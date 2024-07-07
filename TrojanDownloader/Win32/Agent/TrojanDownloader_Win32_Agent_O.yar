
rule TrojanDownloader_Win32_Agent_O{
	meta:
		description = "TrojanDownloader:Win32/Agent.O,SIGNATURE_TYPE_PEHSTR,09 00 08 00 09 00 00 "
		
	strings :
		$a_01_0 = {6f 63 63 75 72 65 64 } //1 occured
		$a_01_1 = {73 74 61 72 74 65 64 } //1 started
		$a_01_2 = {65 6e 64 65 64 } //1 ended
		$a_01_3 = {38 38 2d 38 38 2d 38 38 } //1 88-88-88
		$a_01_4 = {77 68 62 6f 79 } //1 whboy
		$a_01_5 = {31 33 31 34 } //1 1314
		$a_01_6 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 45 78 70 6c 6f 72 65 72 5c 41 64 76 61 6e 63 65 64 5c 46 6f 6c 64 65 72 5c 48 69 64 64 65 6e 5c 53 48 4f 57 41 4c 4c } //1 Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Folder\Hidden\SHOWALL
		$a_01_7 = {25 73 5c 70 72 6f 67 6d 6f 6e 2e 65 78 65 } //1 %s\progmon.exe
		$a_01_8 = {25 73 5c 69 6e 74 65 72 6e 74 2e 65 78 65 } //1 %s\internt.exe
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1) >=8
 
}