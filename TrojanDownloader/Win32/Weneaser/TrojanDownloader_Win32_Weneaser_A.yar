
rule TrojanDownloader_Win32_Weneaser_A{
	meta:
		description = "TrojanDownloader:Win32/Weneaser.A,SIGNATURE_TYPE_PEHSTR,11 00 11 00 07 00 00 "
		
	strings :
		$a_01_0 = {2d 32 30 30 35 2d 73 65 61 72 63 68 2e 63 6f 6d 2f 6e 65 77 31 2e 70 68 70 } //10 -2005-search.com/new1.php
		$a_01_1 = {54 69 6d 65 72 3a 20 43 6c 69 63 6b 65 64 3a } //2 Timer: Clicked:
		$a_01_2 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 49 6e 74 65 72 6e 65 74 20 53 65 74 74 69 6e 67 73 5c 55 73 65 72 20 41 67 65 6e 74 5c 50 6f 73 74 20 50 6c 61 74 66 6f 72 6d } //2 Software\Microsoft\Windows\CurrentVersion\Internet Settings\User Agent\Post Platform
		$a_01_3 = {61 66 66 69 6c 69 61 74 } //1 affiliat
		$a_01_4 = {61 64 76 65 72 74 } //1 advert
		$a_01_5 = {62 61 6e 6e 65 72 } //1 banner
		$a_01_6 = {64 6f 77 6e 6c 6f 61 64 } //1 download
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=17
 
}