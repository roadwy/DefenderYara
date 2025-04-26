
rule TrojanDownloader_Win32_Alphabet{
	meta:
		description = "TrojanDownloader:Win32/Alphabet,SIGNATURE_TYPE_PEHSTR,2e 00 2d 00 0a 00 00 "
		
	strings :
		$a_01_0 = {25 73 5c 25 73 25 73 2e 65 78 65 } //10 %s\%s%s.exe
		$a_01_1 = {68 74 74 70 3a 2f 2f 73 32 2e 62 65 73 74 6d 61 6e 61 67 65 2e 6f 72 67 2f 3f 6e 61 6d 65 3d 25 73 } //10 http://s2.bestmanage.org/?name=%s
		$a_01_2 = {49 6e 74 65 72 6e 65 74 53 65 74 4f 70 74 69 6f 6e 41 } //10 InternetSetOptionA
		$a_01_3 = {49 6e 74 65 72 6e 65 74 43 68 65 63 6b 43 6f 6e 6e 65 63 74 69 6f 6e 41 } //10 InternetCheckConnectionA
		$a_01_4 = {5f 73 65 6c 66 } //1 _self
		$a_01_5 = {61 67 65 6e 74 } //1 agent
		$a_01_6 = {70 6f 77 65 72 } //1 power
		$a_01_7 = {43 6c 69 63 6b 73 } //1 Clicks
		$a_01_8 = {54 6f 46 65 65 64 } //1 ToFeed
		$a_01_9 = {43 6c 69 63 6b 54 69 6d 65 } //1 ClickTime
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*10+(#a_01_3  & 1)*10+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1) >=45
 
}