
rule Backdoor_Linux_Flashback_A{
	meta:
		description = "Backdoor:Linux/Flashback.A,SIGNATURE_TYPE_MACHOHSTR_EXT,08 00 08 00 05 00 00 "
		
	strings :
		$a_01_0 = {49 4f 50 6c 61 74 66 6f 72 6d 55 55 49 44 } //1 IOPlatformUUID
		$a_01_1 = {6c 61 75 6e 63 68 63 74 6c 20 73 65 74 65 6e 76 20 44 59 4c 44 5f 49 4e 53 45 52 54 5f 4c 49 42 52 41 52 49 45 53 } //1 launchctl setenv DYLD_INSERT_LIBRARIES
		$a_01_2 = {53 6e 69 74 63 68 2f 6c 73 64 } //2 Snitch/lsd
		$a_01_3 = {61 64 6f 62 65 73 6f 66 74 77 61 72 65 75 70 64 61 74 65 } //2 adobesoftwareupdate
		$a_01_4 = {48 8d 34 cd 00 00 00 00 48 b8 ab aa aa aa aa aa aa aa 48 f7 e6 48 89 d1 48 c1 e9 02 48 8d 04 49 48 01 c0 48 29 c6 48 83 fe 02 } //5
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*5) >=8
 
}