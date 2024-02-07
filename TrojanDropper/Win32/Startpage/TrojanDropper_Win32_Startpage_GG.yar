
rule TrojanDropper_Win32_Startpage_GG{
	meta:
		description = "TrojanDropper:Win32/Startpage.GG,SIGNATURE_TYPE_PEHSTR,52 00 52 00 0e 00 00 0a 00 "
		
	strings :
		$a_01_0 = {5c 50 72 6f 67 72 61 6d 20 46 69 6c 65 73 5c 70 72 6f 63 65 64 75 72 65 } //0a 00  \Program Files\procedure
		$a_01_1 = {5c 6e 73 52 61 6e 64 6f 6d 2e 64 6c 6c } //0a 00  \nsRandom.dll
		$a_01_2 = {47 65 74 52 61 6e 64 6f 6d } //0a 00  GetRandom
		$a_01_3 = {25 25 5c 57 4d 53 79 73 50 72 39 2e 70 72 78 } //0a 00  %%\WMSysPr9.prx
		$a_01_4 = {4e 6c 63 65 2e 64 6c 6c } //0a 00  Nlce.dll
		$a_01_5 = {77 69 6e 73 68 75 74 64 6f 77 6e 2e 76 62 73 } //0a 00  winshutdown.vbs
		$a_01_6 = {5c 4f 70 65 6e 49 6e 74 65 72 6e 65 74 2e 65 78 65 } //0a 00  \OpenInternet.exe
		$a_01_7 = {23 5c 4d 61 63 5c 4d 61 63 4a 69 65 2e 6b 65 79 } //01 00  #\Mac\MacJie.key
		$a_01_8 = {67 6c 6f 62 65 2e 70 6e 67 } //01 00  globe.png
		$a_01_9 = {68 64 2e 70 6e 67 } //01 00  hd.png
		$a_01_10 = {6d 61 69 6c 2e 70 6e 67 } //01 00  mail.png
		$a_01_11 = {6d 75 73 69 63 2e 70 6e 67 } //01 00  music.png
		$a_01_12 = {6d 79 5f 63 6f 6d 70 75 74 65 72 2e 70 6e 67 } //01 00  my_computer.png
		$a_01_13 = {6e 6f 74 65 70 61 64 2e 70 6e 67 } //00 00  notepad.png
	condition:
		any of ($a_*)
 
}