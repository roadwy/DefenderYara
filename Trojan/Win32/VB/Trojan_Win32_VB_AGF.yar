
rule Trojan_Win32_VB_AGF{
	meta:
		description = "Trojan:Win32/VB.AGF,SIGNATURE_TYPE_PEHSTR,19 00 19 00 0a 00 00 "
		
	strings :
		$a_01_0 = {53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 49 00 6e 00 74 00 65 00 72 00 6e 00 65 00 74 00 20 00 45 00 78 00 70 00 6c 00 6f 00 72 00 65 00 72 00 5c 00 6d 00 61 00 69 00 6e 00 } //10 Software\Microsoft\Internet Explorer\main
		$a_01_1 = {53 00 4f 00 46 00 54 00 57 00 41 00 52 00 45 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 5c 00 52 00 75 00 6e 00 } //10 SOFTWARE\Microsoft\Windows\CurrentVersion\Run
		$a_01_2 = {43 68 72 6f 6d 65 46 63 6b 5c 6f 62 6a } //2 ChromeFck\obj
		$a_01_3 = {5c 00 5c 00 6d 00 65 00 73 00 73 00 65 00 6e 00 67 00 65 00 72 00 2e 00 65 00 78 00 65 00 } //2 \\messenger.exe
		$a_01_4 = {48 00 6f 00 6d 00 65 00 42 00 6c 00 6f 00 63 00 6b 00 65 00 72 00 2e 00 65 00 78 00 65 00 } //2 HomeBlocker.exe
		$a_01_5 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 77 00 77 00 77 00 2e 00 70 00 72 00 6f 00 61 00 72 00 61 00 6d 00 61 00 2e 00 63 00 6f 00 6d 00 } //1 http://www.proarama.com
		$a_01_6 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 77 00 77 00 77 00 2e 00 70 00 6c 00 75 00 73 00 74 00 76 00 61 00 72 00 61 00 6d 00 61 00 2e 00 63 00 6f 00 6d 00 } //1 http://www.plustvarama.com
		$a_01_7 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 77 00 77 00 77 00 2e 00 74 00 72 00 61 00 72 00 61 00 6d 00 61 00 79 00 65 00 72 00 69 00 2e 00 6e 00 65 00 74 00 } //1 http://www.traramayeri.net
		$a_01_8 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 77 00 77 00 77 00 2e 00 66 00 69 00 78 00 61 00 72 00 61 00 62 00 75 00 6c 00 2e 00 63 00 6f 00 6d 00 } //1 http://www.fixarabul.com
		$a_01_9 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 77 00 77 00 77 00 2e 00 66 00 69 00 78 00 61 00 72 00 61 00 73 00 61 00 6e 00 61 00 2e 00 63 00 6f 00 6d 00 } //1 http://www.fixarasana.com
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1) >=25
 
}