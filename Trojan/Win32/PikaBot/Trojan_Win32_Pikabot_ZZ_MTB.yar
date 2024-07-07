
rule Trojan_Win32_Pikabot_ZZ_MTB{
	meta:
		description = "Trojan:Win32/Pikabot.ZZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 08 00 00 "
		
	strings :
		$a_01_0 = {6d 75 65 73 75 6d 2e 64 6e 61 } //1 muesum.dna
		$a_01_1 = {65 00 42 00 75 00 72 00 67 00 65 00 72 00 45 00 76 00 65 00 6e 00 74 00 5f 00 50 00 61 00 73 00 73 00 77 00 6f 00 72 00 64 00 44 00 65 00 74 00 61 00 69 00 6c 00 44 00 69 00 73 00 70 00 6c 00 61 00 79 00 65 00 64 00 } //1 eBurgerEvent_PasswordDetailDisplayed
		$a_01_2 = {41 56 50 61 6d 53 79 6e 63 45 78 63 65 70 74 69 6f 6e 43 6c 69 65 6e 74 44 65 6e 69 65 64 40 70 61 73 73 77 64 6d 67 72 40 61 76 61 73 74 40 63 6f 6d } //1 AVPamSyncExceptionClientDenied@passwdmgr@avast@com
		$a_01_3 = {61 76 63 66 67 3a 2f 2f 73 65 74 74 69 6e 67 73 2f 43 6f 6d 6d 6f 6e 2f 50 61 73 73 77 6f 72 64 48 61 73 68 } //1 avcfg://settings/Common/PasswordHash
		$a_01_4 = {61 76 63 66 67 3a 2f 2f 73 65 74 74 69 6e 67 73 2f 50 61 73 73 77 6f 72 64 73 2f 4c 65 61 6b 43 68 65 63 6b 41 6c } //1 avcfg://settings/Passwords/LeakCheckAl
		$a_01_5 = {2e 61 73 77 2e 70 61 6d 2e 70 72 6f 74 6f 2e 42 72 6f 77 73 65 72 43 72 65 64 65 6e 74 69 61 6c 5c 5c 22 46 } //1 .asw.pam.proto.BrowserCredential\\"F
		$a_01_6 = {52 00 65 00 63 00 65 00 69 00 76 00 65 00 64 00 20 00 48 00 54 00 54 00 50 00 2f 00 30 00 2e 00 39 00 20 00 77 00 68 00 65 00 6e 00 20 00 6e 00 6f 00 74 00 20 00 61 00 6c 00 6c 00 6f 00 77 00 65 00 64 00 } //1 Received HTTP/0.9 when not allowed
		$a_01_7 = {64 00 65 00 63 00 79 00 72 00 69 00 6c 00 6c 00 69 00 63 00 } //1 decyrillic
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=7
 
}