
rule Trojan_Win32_SnakeKeylogger_ZA_MTB{
	meta:
		description = "Trojan:Win32/SnakeKeylogger.ZA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {67 65 74 5f 65 6e 63 72 79 70 74 65 64 50 61 73 73 77 6f 72 64 } //1 get_encryptedPassword
		$a_01_1 = {67 65 74 5f 65 6e 63 72 79 70 74 65 64 55 73 65 72 6e 61 6d 65 } //1 get_encryptedUsername
		$a_01_2 = {67 65 74 5f 74 69 6d 65 50 61 73 73 77 6f 72 64 43 68 61 6e 67 65 64 } //1 get_timePasswordChanged
		$a_01_3 = {67 65 74 5f 70 61 73 73 77 6f 72 64 46 69 65 6c 64 } //1 get_passwordField
		$a_01_4 = {67 65 74 5f 6c 6f 67 69 6e 73 } //1 get_logins
		$a_01_5 = {4b 65 79 4c 6f 67 67 65 72 45 76 65 6e 74 41 72 67 73 45 76 65 6e 74 48 61 6e 64 6c 65 72 } //1 KeyLoggerEventArgsEventHandler
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}