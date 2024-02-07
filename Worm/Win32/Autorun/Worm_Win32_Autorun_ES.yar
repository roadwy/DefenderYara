
rule Worm_Win32_Autorun_ES{
	meta:
		description = "Worm:Win32/Autorun.ES,SIGNATURE_TYPE_PEHSTR,0a 00 0a 00 0a 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //01 00  SOFTWARE\Microsoft\Windows\CurrentVersion\Run
		$a_01_1 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c 4d 61 69 6e } //01 00  Software\Microsoft\Internet Explorer\Main
		$a_01_2 = {68 74 74 70 3a 2f 2f 6b 6b 6b 6b 62 2e 63 6f 6d } //01 00  http://kkkkb.com
		$a_01_3 = {41 75 74 6f 72 75 6e 2e 69 6e 66 } //01 00  Autorun.inf
		$a_01_4 = {5b 41 75 74 6f 52 75 6e 5d } //01 00  [AutoRun]
		$a_01_5 = {43 6f 6d 6d 61 6e 64 3d 44 72 69 76 65 2e 65 78 65 } //01 00  Command=Drive.exe
		$a_01_6 = {51 51 32 30 30 37 69 6e 69 } //01 00  QQ2007ini
		$a_01_7 = {68 70 78 6b 32 30 30 37 } //01 00  hpxk2007
		$a_01_8 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } //01 00  URLDownloadToFileA
		$a_01_9 = {43 3a 5c 57 49 4e 44 4f 57 53 5c 53 59 53 54 45 4d 33 32 5c 51 51 32 30 30 37 5c 51 51 2e 65 78 30 } //00 00  C:\WINDOWS\SYSTEM32\QQ2007\QQ.ex0
	condition:
		any of ($a_*)
 
}