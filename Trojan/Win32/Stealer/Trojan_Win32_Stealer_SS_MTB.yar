
rule Trojan_Win32_Stealer_SS_MTB{
	meta:
		description = "Trojan:Win32/Stealer.SS!MTB,SIGNATURE_TYPE_PEHSTR,13 00 13 00 13 00 00 "
		
	strings :
		$a_01_0 = {46 69 72 65 66 6f 78 20 50 61 73 73 77 6f 72 64 73 } //1 Firefox Passwords
		$a_01_1 = {47 6f 6f 67 6c 65 20 43 68 72 6f 6d 65 20 50 61 73 73 77 6f 72 64 73 } //1 Google Chrome Passwords
		$a_01_2 = {4f 70 65 72 61 20 50 61 73 73 77 6f 72 64 73 } //1 Opera Passwords
		$a_01_3 = {53 45 4c 45 43 54 20 28 53 45 4c 45 43 54 20 63 6f 75 6e 74 28 29 20 46 52 4f 4d 20 6d 6f 7a 5f 6c 6f 67 69 6e 73 29 20 41 53 20 22 74 6f 74 61 6c 22 2c 20 68 6f 73 74 6e 61 6d 65 2c 20 65 6e 63 72 79 70 74 65 64 55 73 65 72 6e 61 6d 65 2c 20 65 6e 63 72 79 70 74 65 64 50 61 73 73 77 6f 72 64 20 46 52 4f 4d 20 6d 6f 7a 5f 6c 6f 67 69 6e 73 } //1 SELECT (SELECT count() FROM moz_logins) AS "total", hostname, encryptedUsername, encryptedPassword FROM moz_logins
		$a_01_4 = {57 69 6e 64 6f 77 73 20 4c 69 76 65 20 4d 65 73 73 65 6e 67 65 72 20 50 61 73 73 77 6f 72 64 73 } //1 Windows Live Messenger Passwords
		$a_01_5 = {44 69 61 6c 75 70 2f 52 41 53 2f 56 50 4e 20 50 61 73 73 77 6f 72 64 73 } //1 Dialup/RAS/VPN Passwords
		$a_01_6 = {49 45 20 4c 6f 67 69 6e 20 50 61 73 73 77 6f 72 64 73 } //1 IE Login Passwords
		$a_01_7 = {49 45 20 43 65 72 74 69 66 69 63 61 74 69 6f 6e 20 50 61 73 73 77 6f 72 64 73 } //1 IE Certification Passwords
		$a_01_8 = {47 6f 6f 67 6c 65 20 54 61 6c 6b 20 50 61 73 73 77 6f 72 64 73 } //1 Google Talk Passwords
		$a_01_9 = {4f 75 74 6c 6f 6f 6b 20 50 61 73 73 77 6f 72 64 73 } //1 Outlook Passwords
		$a_01_10 = {49 4d 41 50 20 50 61 73 73 77 6f 72 64 } //1 IMAP Password
		$a_01_11 = {50 4f 50 33 20 50 61 73 73 77 6f 72 64 } //1 POP3 Password
		$a_01_12 = {73 65 6e 64 70 61 73 73 77 6f 72 64 } //1 sendpassword
		$a_01_13 = {42 45 47 49 4e 20 43 4c 49 50 42 4f 41 52 44 } //1 BEGIN CLIPBOARD
		$a_01_14 = {65 6e 63 72 79 70 74 65 64 55 73 65 72 6e 61 6d 65 } //1 encryptedUsername
		$a_01_15 = {6d 6f 7a 69 6c 6c 61 77 69 6e 64 6f 77 63 6c 61 73 73 } //1 mozillawindowclass
		$a_01_16 = {47 65 74 54 65 6d 70 50 61 74 68 41 } //1 GetTempPathA
		$a_01_17 = {49 73 43 6c 69 70 62 6f 61 72 64 46 6f 72 6d 61 74 41 76 61 69 6c 61 62 6c 65 } //1 IsClipboardFormatAvailable
		$a_01_18 = {47 65 74 43 6c 69 70 62 6f 61 72 64 44 61 74 61 } //1 GetClipboardData
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1+(#a_01_12  & 1)*1+(#a_01_13  & 1)*1+(#a_01_14  & 1)*1+(#a_01_15  & 1)*1+(#a_01_16  & 1)*1+(#a_01_17  & 1)*1+(#a_01_18  & 1)*1) >=19
 
}