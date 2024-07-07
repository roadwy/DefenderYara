
rule TrojanDownloader_Win32_Renos_FJ{
	meta:
		description = "TrojanDownloader:Win32/Renos.FJ,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 08 00 00 "
		
	strings :
		$a_01_0 = {56 73 65 67 6f 20 55 52 4c 6f 76 } //3 Vsego URLov
		$a_01_1 = {2f 73 2f 65 78 78 2e 70 68 70 } //3 /s/exx.php
		$a_01_2 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //3 SOFTWARE\Microsoft\Windows\CurrentVersion\Run
		$a_01_3 = {63 6c 69 63 6b 65 72 35 30 54 69 6d 65 72 } //1 clicker50Timer
		$a_01_4 = {4c 69 6e 6b 6f 76 20 62 6f 73 68 65 20 6e 65 74 20 47 6f 54 6f 20 77 61 69 74 } //1 Linkov boshe net GoTo wait
		$a_01_5 = {52 45 4d 41 4b 45 44 21 } //1 REMAKED!
		$a_01_6 = {4c 65 6e 67 74 68 00 00 00 01 00 00 6c 69 6e 6b 73 00 00 00 00 01 00 00 44 6f 63 75 6d 65 6e 74 00 } //1
		$a_03_7 = {4c 69 6e 65 73 2e 53 74 72 69 6e 67 73 01 06 90 01 01 68 74 74 70 3a 2f 2f 90 00 } //1
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*3+(#a_01_2  & 1)*3+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_03_7  & 1)*1) >=11
 
}