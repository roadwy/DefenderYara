
rule Trojan_Win32_Hupigon_GME_MTB{
	meta:
		description = "Trojan:Win32/Hupigon.GME!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 0e 00 00 01 00 "
		
	strings :
		$a_01_0 = {31 36 37 2e 31 31 34 2e 30 2e 31 34 34 } //01 00  167.114.0.144
		$a_80_1 = {68 74 74 70 3a 2f 2f 77 77 77 2e 66 6f 6c 64 65 72 2d 68 69 64 65 72 2d 73 74 65 61 6c 74 68 2e 63 6f 6d 2f 69 70 32 2e 73 68 74 6d 6c } //http://www.folder-hider-stealth.com/ip2.shtml  01 00 
		$a_01_2 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //01 00  SOFTWARE\Microsoft\Windows\CurrentVersion\Run
		$a_01_3 = {50 61 73 73 77 6f 72 64 } //01 00  Password
		$a_80_4 = {5c 70 69 63 2e 6a 70 67 } //\pic.jpg  01 00 
		$a_80_5 = {5c 77 77 77 2e 42 61 74 } //\www.Bat  01 00 
		$a_80_6 = {5c 64 65 73 6b 74 6f 70 2e 69 6e 69 } //\desktop.ini  01 00 
		$a_80_7 = {5c 64 6c 6c 5c 66 6c 67 66 2e 64 6c 6c } //\dll\flgf.dll  01 00 
		$a_80_8 = {5c 65 78 74 69 70 2e 74 78 74 } //\extip.txt  01 00 
		$a_80_9 = {77 69 6e 73 79 73 74 33 32 2e 65 78 65 } //winsyst32.exe  01 00 
		$a_01_10 = {74 6d 72 53 74 6f 70 4b 69 6c 6c } //01 00  tmrStopKill
		$a_01_11 = {63 6d 64 43 6f 6e 6e 65 63 74 } //01 00  cmdConnect
		$a_01_12 = {63 6d 64 44 6f 77 6e 6c 6f 61 64 } //01 00  cmdDownload
		$a_01_13 = {4b 69 6c 6c 54 69 6d 65 72 } //00 00  KillTimer
	condition:
		any of ($a_*)
 
}