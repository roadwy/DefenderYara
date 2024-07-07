
rule TrojanSpy_BAT_KeyLogger_ARA_MTB{
	meta:
		description = "TrojanSpy:BAT/KeyLogger.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_80_0 = {63 3a 5c 55 73 65 72 73 5c 6c 61 62 5c 44 65 73 6b 74 6f 70 5c 6c 61 62 5c 6b 65 79 6c 6f 67 2e 74 78 74 } //c:\Users\lab\Desktop\lab\keylog.txt  2
		$a_80_1 = {4b 45 59 4c 4f 47 47 45 52 } //KEYLOGGER  2
	condition:
		((#a_80_0  & 1)*2+(#a_80_1  & 1)*2) >=4
 
}
rule TrojanSpy_BAT_KeyLogger_ARA_MTB_2{
	meta:
		description = "TrojanSpy:BAT/KeyLogger.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 06 00 00 "
		
	strings :
		$a_01_0 = {06 13 07 11 07 17 2e 0b 11 07 20 01 80 ff ff fe 01 2b 01 17 13 08 11 08 2c 2c } //2
		$a_01_1 = {63 68 6b 53 79 73 45 76 65 } //2 chkSysEve
		$a_80_2 = {3a 5c 57 69 6e 64 6f 77 73 20 48 61 6e 64 6c 65 72 5c 48 61 6e 64 6c 65 72 2e 64 61 74 } //:\Windows Handler\Handler.dat  2
		$a_80_3 = {4b 65 79 73 74 72 6f 6b 65 73 20 73 61 76 65 64 20 66 72 6f 6d 20 75 73 65 72 } //Keystrokes saved from user  2
		$a_01_4 = {53 65 6e 64 4d 61 69 6c } //1 SendMail
		$a_01_5 = {49 43 72 65 64 65 6e 74 69 61 6c 73 42 79 48 6f 73 74 } //1 ICredentialsByHost
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_80_2  & 1)*2+(#a_80_3  & 1)*2+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=10
 
}