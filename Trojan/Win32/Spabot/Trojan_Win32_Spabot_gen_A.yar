
rule Trojan_Win32_Spabot_gen_A{
	meta:
		description = "Trojan:Win32/Spabot.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,ffffffc8 00 ffffffc8 00 12 00 00 "
		
	strings :
		$a_00_0 = {73 70 61 6d 62 6f 74 } //50 spambot
		$a_00_1 = {4d 41 49 4c 20 46 52 4f 4d 3a 20 3c 25 73 3e } //50 MAIL FROM: <%s>
		$a_00_2 = {52 43 50 54 20 54 4f 3a 3c 25 73 3e } //50 RCPT TO:<%s>
		$a_00_3 = {68 74 74 70 3a 2f 2f 61 75 74 6f 65 73 63 72 6f 77 70 61 79 2e 63 6f 6d 2f 73 2e 70 68 70 } //50 http://autoescrowpay.com/s.php
		$a_00_4 = {4d 4a 56 3a 25 64 20 4d 4e 56 3a 25 64 20 50 49 44 3a 25 64 20 42 75 69 6c 64 3a 25 64 20 43 6f 6d 6d 65 6e 74 3a 25 73 } //50 MJV:%d MNV:%d PID:%d Build:%d Comment:%s
		$a_02_5 = {2e 63 6f 6d 00 [0-50] 2e 63 6f 6d 00 [0-50] 2e 63 6f 6d 00 [0-50] 2e 63 6f 6d 00 [0-50] 2e 63 6f 6d 00 } //50
		$a_00_6 = {41 4f 4c 20 37 2e 30 20 66 6f 72 20 57 69 6e 64 6f 77 73 } //5 AOL 7.0 for Windows
		$a_00_7 = {43 61 6c 79 70 73 6f 20 56 65 72 73 69 6f 6e } //5 Calypso Version
		$a_00_8 = {65 47 72 6f 75 70 73 20 4d 65 73 73 61 67 65 20 50 6f 73 74 65 72 } //5 eGroups Message Poster
		$a_00_9 = {49 6e 74 65 72 6e 65 74 20 4d 61 69 6c 20 53 65 72 76 69 63 65 20 28 35 2e 35 2e 32 36 35 30 2e 32 31 29 } //5 Internet Mail Service (5.5.2650.21)
		$a_00_10 = {4d 61 69 6c 47 61 74 65 20 76 33 2e 30 } //5 MailGate v3.0
		$a_00_11 = {4d 49 4d 45 2d 74 6f 6f 6c 73 20 34 2e 31 30 34 20 28 45 6e 74 69 74 79 20 34 2e 31 31 36 29 } //5 MIME-tools 4.104 (Entity 4.116)
		$a_00_12 = {4d 75 74 74 2f 31 2e 35 2e 31 69 } //5 Mutt/1.5.1i
		$a_00_13 = {50 65 67 61 73 75 73 20 4d 61 69 6c 20 66 6f 72 20 57 69 6e 33 32 20 28 76 32 2e 35 33 2f 52 31 29 } //5 Pegasus Mail for Win32 (v2.53/R1)
		$a_00_14 = {50 4f 62 6f 78 20 49 49 20 62 65 74 61 31 2e 30 } //5 PObox II beta1.0
		$a_00_15 = {51 55 41 4c 43 4f 4d 4d 20 57 69 6e 64 6f 77 73 20 45 75 64 6f 72 61 } //5 QUALCOMM Windows Eudora
		$a_00_16 = {53 6d 61 72 74 4d 61 69 6c 65 72 20 56 65 72 73 69 6f 6e 20 31 2e 35 36 20 2d 47 65 72 6d 61 6e 20 50 72 69 76 61 74 20 4c 69 63 65 6e 73 65 2d } //5 SmartMailer Version 1.56 -German Privat License-
		$a_00_17 = {53 79 6c 70 68 65 65 64 20 76 65 72 73 69 6f 6e 20 30 2e 38 2e 32 20 28 47 54 4b 2b 20 31 2e 32 2e 31 30 3b 20 69 35 38 36 2d 61 6c 74 2d 6c 69 6e 75 78 29 } //5 Sylpheed version 0.8.2 (GTK+ 1.2.10; i586-alt-linux)
	condition:
		((#a_00_0  & 1)*50+(#a_00_1  & 1)*50+(#a_00_2  & 1)*50+(#a_00_3  & 1)*50+(#a_00_4  & 1)*50+(#a_02_5  & 1)*50+(#a_00_6  & 1)*5+(#a_00_7  & 1)*5+(#a_00_8  & 1)*5+(#a_00_9  & 1)*5+(#a_00_10  & 1)*5+(#a_00_11  & 1)*5+(#a_00_12  & 1)*5+(#a_00_13  & 1)*5+(#a_00_14  & 1)*5+(#a_00_15  & 1)*5+(#a_00_16  & 1)*5+(#a_00_17  & 1)*5) >=200
 
}