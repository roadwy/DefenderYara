
rule Trojan_Win32_ClipBanker_GJ_MTB{
	meta:
		description = "Trojan:Win32/ClipBanker.GJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {32 33 39 2e 32 35 35 2e 32 35 35 2e 32 35 30 } //01 00  239.255.255.250
		$a_01_1 = {31 38 35 2e 32 31 35 2e 31 31 33 2e 38 34 } //01 00  185.215.113.84
		$a_80_2 = {2f 63 20 73 74 61 72 74 20 2e 5c 25 73 20 26 20 73 74 61 72 74 20 2e 5c 25 73 5c 56 6f 6c 44 72 69 76 65 72 2e 65 78 65 } ///c start .\%s & start .\%s\VolDriver.exe  01 00 
		$a_80_3 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //Software\Microsoft\Windows\CurrentVersion\Run  01 00 
		$a_80_4 = {64 65 73 6b 74 6f 70 2e 69 6e 69 } //desktop.ini  01 00 
		$a_01_5 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 } //00 00  URLDownloadToFile
	condition:
		any of ($a_*)
 
}