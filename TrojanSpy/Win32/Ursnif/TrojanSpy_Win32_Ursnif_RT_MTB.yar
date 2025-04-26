
rule TrojanSpy_Win32_Ursnif_RT_MTB{
	meta:
		description = "TrojanSpy:Win32/Ursnif.RT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 0a 00 00 "
		
	strings :
		$a_01_0 = {2e 6f 6e 69 6f 6e } //1 .onion
		$a_01_1 = {45 64 48 6f 6f 6b } //1 EdHook
		$a_01_2 = {4f 70 48 6f 6f 6b } //1 OpHook
		$a_01_3 = {68 74 74 70 3a 2f 2f 63 6f 6e 73 74 69 74 75 74 69 6f 6e 2e 6f 72 67 2f 75 73 64 65 63 6c 61 72 2e 74 78 74 } //10 http://constitution.org/usdeclar.txt
		$a_01_4 = {65 6e 63 72 79 70 74 65 64 55 73 65 72 6e 61 6d 65 } //1 encryptedUsername
		$a_01_5 = {65 6e 63 72 79 70 74 65 64 50 61 73 73 77 6f 72 64 } //1 encryptedPassword
		$a_01_6 = {49 6e 74 65 72 6e 65 74 47 65 74 43 6f 6f 6b 69 65 41 } //1 InternetGetCookieA
		$a_00_7 = {49 00 4d 00 41 00 50 00 20 00 50 00 61 00 73 00 73 00 77 00 6f 00 72 00 64 00 } //1 IMAP Password
		$a_00_8 = {50 00 4f 00 50 00 33 00 20 00 50 00 61 00 73 00 73 00 77 00 6f 00 72 00 64 00 } //1 POP3 Password
		$a_00_9 = {53 00 4d 00 54 00 50 00 20 00 50 00 61 00 73 00 73 00 77 00 6f 00 72 00 64 00 } //1 SMTP Password
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*10+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_00_7  & 1)*1+(#a_00_8  & 1)*1+(#a_00_9  & 1)*1) >=16
 
}