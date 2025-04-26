
rule TrojanDownloader_Win32_Agent_ZDJ{
	meta:
		description = "TrojanDownloader:Win32/Agent.ZDJ,SIGNATURE_TYPE_PEHSTR,09 00 09 00 09 00 00 "
		
	strings :
		$a_01_0 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //1 SOFTWARE\Microsoft\Windows\CurrentVersion\Run
		$a_01_1 = {68 74 74 70 3a 2f 2f 77 77 77 2e 4b 4a 44 68 65 6e 64 69 65 6c 64 69 6f 75 79 75 2e 43 4f 4d 2f 43 46 44 41 54 41 2e 69 6d 61 3f 63 63 6f 64 65 3d 25 73 26 63 66 64 61 74 61 63 63 3d 25 73 26 67 6d 74 3d 25 64 } //1 http://www.KJDhendieldiouyu.COM/CFDATA.ima?ccode=%s&cfdatacc=%s&gmt=%d
		$a_01_2 = {61 73 64 66 6a 6b 6c 75 69 6f 70 2e 63 6f 6d } //1 asdfjkluiop.com
		$a_01_3 = {73 77 65 65 70 73 74 61 6b 65 73 73 2e 63 6f 6d } //1 sweepstakess.com
		$a_01_4 = {68 6f 74 78 78 78 74 76 2e 63 6f 6d } //1 hotxxxtv.com
		$a_01_5 = {66 72 65 65 70 6f 72 6e 74 6f 64 61 79 2e 6e 65 74 } //1 freeporntoday.net
		$a_01_6 = {66 72 65 65 70 6f 72 6e 6e 6f 77 2e 6e 65 74 } //1 freepornnow.net
		$a_01_7 = {70 6f 72 6e 31 2e 6f 72 67 } //1 porn1.org
		$a_01_8 = {76 69 72 67 69 6e 73 } //1 virgins
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1) >=9
 
}