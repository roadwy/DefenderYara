
rule Trojan_Win32_Phorpiex_RPY_MTB{
	meta:
		description = "Trojan:Win32/Phorpiex.RPY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 01 00 "
		
	strings :
		$a_01_0 = {74 00 77 00 69 00 7a 00 74 00 2e 00 6e 00 65 00 74 00 } //01 00  twizt.net
		$a_01_1 = {6c 00 73 00 6c 00 75 00 74 00 2e 00 65 00 78 00 65 00 } //01 00  lslut.exe
		$a_01_2 = {53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 5c 00 52 00 75 00 6e 00 } //01 00  Software\Microsoft\Windows\CurrentVersion\Run
		$a_01_3 = {57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 20 00 53 00 65 00 72 00 76 00 69 00 63 00 65 00 } //01 00  Windows Service
		$a_01_4 = {4d 00 6f 00 7a 00 69 00 6c 00 6c 00 61 00 2f 00 35 00 2e 00 30 00 } //01 00  Mozilla/5.0
		$a_01_5 = {25 00 74 00 65 00 6d 00 70 00 25 00 } //01 00  %temp%
		$a_01_6 = {66 72 65 65 75 6b 72 61 69 6e 65 } //01 00  freeukraine
		$a_01_7 = {66 75 63 6b 70 75 74 2e 69 6e } //00 00  fuckput.in
	condition:
		any of ($a_*)
 
}