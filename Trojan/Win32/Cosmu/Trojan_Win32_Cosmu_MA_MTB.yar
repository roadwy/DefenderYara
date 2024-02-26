
rule Trojan_Win32_Cosmu_MA_MTB{
	meta:
		description = "Trojan:Win32/Cosmu.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 07 00 00 03 00 "
		
	strings :
		$a_01_0 = {33 d2 66 89 95 e2 fc ff ff 66 8b 8d dc fc ff ff 33 c0 8d 95 dc fc ff ff 66 85 c9 0f 84 } //03 00 
		$a_81_1 = {3a 5c 6c 6f 67 62 6f 74 2e 74 78 74 } //03 00  :\logbot.txt
		$a_01_2 = {42 00 6f 00 74 00 2e 00 65 00 78 00 65 00 3a 00 } //01 00  Bot.exe:
		$a_01_3 = {65 00 6a 00 65 00 63 00 74 00 69 00 6e 00 67 00 } //01 00  ejecting
		$a_01_4 = {4d 00 6f 00 6e 00 69 00 74 00 6f 00 72 00 69 00 6e 00 67 00 } //01 00  Monitoring
		$a_01_5 = {53 00 4f 00 46 00 54 00 57 00 41 00 52 00 45 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 20 00 4e 00 54 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 5c 00 53 00 76 00 63 00 48 00 6f 00 73 00 74 00 } //01 00  SOFTWARE\Microsoft\Windows NT\CurrentVersion\SvcHost
		$a_01_6 = {53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 5c 00 52 00 75 00 6e 00 } //00 00  Software\Microsoft\Windows\CurrentVersion\Run
	condition:
		any of ($a_*)
 
}