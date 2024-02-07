
rule Trojan_Win32_Tnega_GIS_MTB{
	meta:
		description = "Trojan:Win32/Tnega.GIS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 01 00 "
		
	strings :
		$a_01_0 = {77 77 77 2e 59 61 6e 6a 69 65 2e 63 6f 6d } //01 00  www.Yanjie.com
		$a_01_1 = {68 74 74 70 3a 2f 2f 31 30 31 2e 33 35 2e 31 38 2e 32 35 34 2f 34 34 34 2e 65 78 65 } //01 00  http://101.35.18.254/444.exe
		$a_01_2 = {66 75 63 6b 79 6f 75 } //01 00  fuckyou
		$a_01_3 = {5c 31 31 31 2e 65 78 65 } //01 00  \111.exe
		$a_01_4 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //01 00  Software\Microsoft\Windows\CurrentVersion\Run
		$a_01_5 = {43 3a 5c 50 72 6f 67 72 61 6d 44 61 74 61 5c 34 34 34 2e 65 78 65 } //01 00  C:\ProgramData\444.exe
		$a_01_6 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 } //01 00  URLDownloadToFile
		$a_01_7 = {53 68 65 6c 6c 45 78 65 63 75 74 65 } //00 00  ShellExecute
	condition:
		any of ($a_*)
 
}