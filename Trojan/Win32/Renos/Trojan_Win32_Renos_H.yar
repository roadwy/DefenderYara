
rule Trojan_Win32_Renos_H{
	meta:
		description = "Trojan:Win32/Renos.H,SIGNATURE_TYPE_PEHSTR_EXT,64 00 64 00 0a 00 00 "
		
	strings :
		$a_02_0 = {68 74 74 70 3a 2f 2f 64 6f 77 6e 6c 6f 61 64 2e 90 02 30 2e 63 6f 6d 2f 90 02 20 2e 65 78 65 90 00 } //10
		$a_00_1 = {2f 53 20 2f 41 49 44 3d } //10 /S /AID=
		$a_00_2 = {68 74 74 70 3a 2f 2f 61 6c 66 61 70 6f 72 74 61 6c 2e 63 6f 6d 2f 63 } //10 http://alfaportal.com/c
		$a_00_3 = {43 4c 53 49 44 5c 7b 33 35 37 41 38 37 45 44 2d 33 45 35 44 2d 34 33 37 64 2d 42 33 33 34 2d 44 45 42 37 45 42 34 39 38 32 41 33 7d } //10 CLSID\{357A87ED-3E5D-437d-B334-DEB7EB4982A3}
		$a_00_4 = {70 72 6f 67 72 61 6d 2e 65 78 65 } //10 program.exe
		$a_00_5 = {5c 73 63 72 65 65 6e 2e 68 74 6d 6c } //10 \screen.html
		$a_00_6 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //10 Software\Microsoft\Windows\CurrentVersion\Run
		$a_00_7 = {41 6e 74 69 76 69 72 75 73 47 6f 6c 64 } //10 AntivirusGold
		$a_00_8 = {49 6e 74 65 6c 20 73 79 73 74 65 6d 20 74 6f 6f 6c } //10 Intel system tool
		$a_00_9 = {77 69 6e 69 6e 65 74 } //10 wininet
	condition:
		((#a_02_0  & 1)*10+(#a_00_1  & 1)*10+(#a_00_2  & 1)*10+(#a_00_3  & 1)*10+(#a_00_4  & 1)*10+(#a_00_5  & 1)*10+(#a_00_6  & 1)*10+(#a_00_7  & 1)*10+(#a_00_8  & 1)*10+(#a_00_9  & 1)*10) >=100
 
}