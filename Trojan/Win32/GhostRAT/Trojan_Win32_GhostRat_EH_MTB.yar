
rule Trojan_Win32_GhostRat_EH_MTB{
	meta:
		description = "Trojan:Win32/GhostRat.EH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {31 37 32 2e 31 36 2e 31 2c 31 30 2e 31 30 32 2e 31 39 37 2c 31 30 2e 38 35 2e 31 39 30 2c 31 30 2e 31 30 32 2e 31 30 37 2c 31 30 2e 33 37 2e 32 33 39 2c 31 30 2e 32 34 2e 31 38 32 2c 31 30 2e 37 31 2e 31 32 39 2c 31 30 2e 39 2e 31 37 34 } //01 00  172.16.1,10.102.197,10.85.190,10.102.107,10.37.239,10.24.182,10.71.129,10.9.174
		$a_01_1 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //01 00  Software\Microsoft\Windows\CurrentVersion\Run
		$a_01_2 = {33 36 30 74 72 61 79 2e 65 78 65 } //01 00  360tray.exe
		$a_01_3 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 57 } //01 00  URLDownloadToFileW
		$a_01_4 = {62 00 66 00 73 00 76 00 63 00 2e 00 65 00 78 00 65 00 } //01 00  bfsvc.exe
		$a_81_5 = {2f 63 20 73 63 68 74 61 73 6b 73 20 2f 63 72 65 61 74 65 20 2f 73 63 20 6f 6e 6c 6f 67 6f 6e 20 2f 74 6e } //00 00  /c schtasks /create /sc onlogon /tn
	condition:
		any of ($a_*)
 
}