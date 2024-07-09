
rule PWS_Win32_Ldpinch_AF{
	meta:
		description = "PWS:Win32/Ldpinch.AF,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 0e 00 00 "
		
	strings :
		$a_01_0 = {4d 41 49 4c 20 46 52 4f 4d 3a 20 77 65 72 74 79 40 75 73 61 2e 6e 65 74 } //1 MAIL FROM: werty@usa.net
		$a_01_1 = {53 75 62 6a 65 63 74 3a 66 6f 72 20 79 6f 75 } //1 Subject:for you
		$a_01_2 = {68 74 74 70 3a 2f 2f 77 77 2e 66 62 69 2e 67 6f 76 2f 77 6f 72 6c 64 77 69 64 65 64 6c 6f 67 73 2f 61 64 64 74 6f 62 61 73 65 2e 61 73 70 } //1 http://ww.fbi.gov/worldwidedlogs/addtobase.asp
		$a_01_3 = {68 74 74 70 3a 2f 2f 77 77 77 2e 66 62 69 2e 67 6f 76 2f 69 6e 64 65 78 2e 68 74 6d } //1 http://www.fbi.gov/index.htm
		$a_01_4 = {77 69 6e 69 6e 65 74 63 61 63 68 65 63 72 65 64 65 6e 74 69 61 6c 73 } //1 wininetcachecredentials
		$a_01_5 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 49 6e 74 65 72 6e 65 74 20 41 63 63 6f 75 6e 74 20 4d 61 6e 61 67 65 72 5c 41 63 63 6f 75 6e 74 73 } //1 SOFTWARE\Microsoft\Internet Account Manager\Accounts
		$a_01_6 = {50 4f 50 33 20 50 61 73 73 77 6f 72 64 32 } //1 POP3 Password2
		$a_01_7 = {50 4f 50 33 20 53 65 72 76 65 72 } //1 POP3 Server
		$a_01_8 = {50 4f 50 33 20 55 73 65 72 20 4e 61 6d 65 } //1 POP3 User Name
		$a_01_9 = {49 4d 41 50 20 50 61 73 73 77 6f 72 64 32 } //1 IMAP Password2
		$a_01_10 = {49 4d 41 50 20 53 65 72 76 65 72 } //1 IMAP Server
		$a_01_11 = {49 4d 41 50 20 55 73 65 72 20 4e 61 6d 65 } //1 IMAP User Name
		$a_01_12 = {69 6e 65 74 63 6f 6d 6d 20 73 65 72 76 65 72 20 70 61 73 73 77 6f 72 64 73 } //1 inetcomm server passwords
		$a_02_13 = {0b c0 75 7c 8d b5 ?? ?? ff ff 81 3e 68 74 74 70 75 6e 8d 85 ?? ?? ff ff 50 e8 ?? ?? 00 00 81 7c 30 fc 44 61 74 61 75 58 eb } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1+(#a_01_12  & 1)*1+(#a_02_13  & 1)*1) >=14
 
}