
rule Trojan_Win32_Kimusky_PA_MTB{
	meta:
		description = "Trojan:Win32/Kimusky.PA!MTB,SIGNATURE_TYPE_PEHSTR,0a 00 0a 00 0a 00 00 "
		
	strings :
		$a_01_0 = {2f 73 20 2f 6e 20 2f 69 20 4e 65 77 41 43 74 2e 64 61 74 } //1 /s /n /i NewACt.dat
		$a_01_1 = {72 6e 73 2e 62 61 74 } //1 rns.bat
		$a_01_2 = {3a 52 65 70 65 61 74 31 0d 0a 64 65 6c 20 22 25 73 22 0d 0a 69 66 20 65 78 69 73 74 20 22 25 73 22 20 67 6f 74 6f 20 52 65 70 65 61 74 31 0d 0a 64 65 6c 20 22 25 73 22 } //1
		$a_01_3 = {61 6e 74 69 63 68 72 69 73 74 2e 6f 72 2e 6b 72 } //1 antichrist.or.kr
		$a_01_4 = {46 2e 70 68 70 } //1 F.php
		$a_01_5 = {2f 64 61 74 61 2f 63 68 65 64 69 74 6f 72 2f 64 69 72 31 } //1 /data/cheditor/dir1
		$a_01_6 = {50 61 70 75 61 20 67 6c 6f 72 69 61 } //1 Papua gloria
		$a_01_7 = {5c 6d 61 6b 65 48 77 70 5c 42 69 6e 5c 6d 61 6b 65 48 77 70 2e 70 64 62 } //1 \makeHwp\Bin\makeHwp.pdb
		$a_01_8 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //1 SOFTWARE\Microsoft\Windows\CurrentVersion\Run
		$a_01_9 = {6c 79 72 69 63 } //1 lyric
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1) >=10
 
}