
rule Worm_Win32_Autorun_DA{
	meta:
		description = "Worm:Win32/Autorun.DA,SIGNATURE_TYPE_PEHSTR,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {61 75 74 6f 72 75 6e 2e 69 6e 66 } //01 00  autorun.inf
		$a_01_1 = {5b 41 75 74 6f 52 75 6e 5d } //01 00  [AutoRun]
		$a_01_2 = {73 68 65 6c 6c 5c 6f 70 65 6e 5c 43 6f 6d 6d 61 6e 64 3d 6c 63 67 2e 65 78 65 } //01 00  shell\open\Command=lcg.exe
		$a_01_3 = {48 4b 43 55 5c 53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c 4d 61 69 6e } //01 00  HKCU\Software\Microsoft\Internet Explorer\Main
		$a_01_4 = {48 4b 4c 4d 5c 53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //01 00  HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
		$a_01_5 = {68 74 74 70 3a 2f 2f 63 63 2e 77 7a 78 71 79 2e 63 6f 6d 2f 74 74 2f 6d 6d 2e 65 78 65 } //00 00  http://cc.wzxqy.com/tt/mm.exe
	condition:
		any of ($a_*)
 
}