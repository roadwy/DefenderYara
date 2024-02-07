
rule Spammer_Win32_Mailbot_K{
	meta:
		description = "Spammer:Win32/Mailbot.K,SIGNATURE_TYPE_PEHSTR,0b 00 0b 00 0b 00 00 01 00 "
		
	strings :
		$a_01_0 = {4d 69 63 72 6f 73 6f 66 74 20 56 69 73 75 61 6c 20 43 2b 2b 20 52 75 6e 74 69 6d 65 20 4c 69 62 72 61 72 79 } //01 00  Microsoft Visual C++ Runtime Library
		$a_01_1 = {4d 41 49 4c 20 46 52 4f 4d } //01 00  MAIL FROM
		$a_01_2 = {52 43 50 54 20 54 4f } //01 00  RCPT TO
		$a_01_3 = {68 65 6c 70 65 72 75 62 66 6c 2e 65 78 65 } //01 00  helperubfl.exe
		$a_01_4 = {75 62 66 6c 2e 65 78 65 } //01 00  ubfl.exe
		$a_01_5 = {75 70 64 61 74 65 75 62 66 6c 2e 65 78 65 } //01 00  updateubfl.exe
		$a_01_6 = {63 62 6c 2e 61 62 75 73 65 61 74 2e 6f 72 67 2f 6c 6f 6f 6b 75 70 2e 63 67 69 } //01 00  cbl.abuseat.org/lookup.cgi
		$a_01_7 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //01 00  SOFTWARE\Microsoft\Windows\CurrentVersion\Run
		$a_01_8 = {43 72 65 61 74 65 4d 75 74 65 78 41 } //01 00  CreateMutexA
		$a_01_9 = {48 74 74 70 4f 70 65 6e 52 65 71 75 65 73 74 41 } //01 00  HttpOpenRequestA
		$a_01_10 = {49 6e 74 65 72 6e 65 74 4f 70 65 6e 55 72 6c 41 } //00 00  InternetOpenUrlA
	condition:
		any of ($a_*)
 
}