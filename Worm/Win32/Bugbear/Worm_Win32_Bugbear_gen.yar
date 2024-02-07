
rule Worm_Win32_Bugbear_gen{
	meta:
		description = "Worm:Win32/Bugbear.gen,SIGNATURE_TYPE_PEHSTR,0b 00 0b 00 0b 00 00 01 00 "
		
	strings :
		$a_01_0 = {4b 65 79 6c 6f 67 64 6c 6c 2e 64 6c 6c } //01 00  Keylogdll.dll
		$a_01_1 = {4c 61 62 73 5c 5a 6f 6e 65 41 6c 61 72 6d 5c 5a 6f 6e 65 41 6c 61 72 6d 2e 65 78 65 } //01 00  Labs\ZoneAlarm\ZoneAlarm.exe
		$a_01_2 = {5a 61 62 63 64 65 66 67 68 69 6a 6b 6c 6d 6e 6f 70 71 72 73 74 75 76 77 78 79 7a 30 31 32 33 34 35 36 37 38 39 2b 2f } //01 00  Zabcdefghijklmnopqrstuvwxyz0123456789+/
		$a_01_3 = {48 4b 45 59 5f 4c 4f 43 41 4c 5f 4d 41 43 48 49 4e 45 5c 53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //01 00  HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run
		$a_01_4 = {4d 41 49 4c 20 46 52 4f 4d 3a 3c 25 73 3e } //01 00  MAIL FROM:<%s>
		$a_01_5 = {52 43 50 54 20 54 4f 3a 3c 25 73 3e } //01 00  RCPT TO:<%s>
		$a_01_6 = {62 75 67 62 65 61 72 } //01 00  bugbear
		$a_01_7 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 45 78 70 6c 6f 72 65 72 5c 53 68 65 6c 6c 20 46 6f 6c 64 65 72 73 } //01 00  SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders
		$a_01_8 = {58 2d 4d 61 69 6c 65 72 3a 20 4d 69 63 72 6f 73 6f 66 74 20 4f 75 74 6c 6f 6f 6b 20 45 78 70 72 65 73 73 20 36 2e 30 30 2e 32 36 30 30 2e 30 30 30 30 } //01 00  X-Mailer: Microsoft Outlook Express 6.00.2600.0000
		$a_01_9 = {43 6f 6e 74 72 6f 6c 53 65 74 5c 53 65 72 76 69 63 65 73 5c 54 63 70 69 70 5c 50 61 72 61 6d 65 74 65 72 73 } //01 00  ControlSet\Services\Tcpip\Parameters
		$a_01_10 = {53 75 62 6a 65 63 74 3a 20 48 65 6c 6c 6f 21 } //00 00  Subject: Hello!
	condition:
		any of ($a_*)
 
}