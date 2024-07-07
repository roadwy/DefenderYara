
rule TrojanSpy_BAT_Rapzo{
	meta:
		description = "TrojanSpy:BAT/Rapzo,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 08 00 09 00 00 "
		
	strings :
		$a_00_0 = {50 00 61 00 69 00 6e 00 20 00 4c 00 6f 00 67 00 67 00 65 00 72 00 } //2 Pain Logger
		$a_01_1 = {6d 73 6e 5f 66 75 63 6b 5f 78 } //2 msn_fuck_x
		$a_00_2 = {5c 00 63 00 64 00 6b 00 65 00 79 00 73 00 2e 00 74 00 78 00 74 00 } //1 \cdkeys.txt
		$a_01_3 = {43 49 45 37 50 61 73 73 77 6f 72 64 73 } //1 CIE7Passwords
		$a_01_4 = {43 4d 53 4e 4d 65 73 73 65 6e 67 65 72 50 61 73 73 77 6f 72 64 73 } //1 CMSNMessengerPasswords
		$a_01_5 = {73 65 74 5f 6b 62 48 6f 6f 6b } //1 set_kbHook
		$a_01_6 = {44 65 6c 65 74 65 4d 6f 7a 69 6c 6c 61 43 6f 6f 6b 69 65 73 } //1 DeleteMozillaCookies
		$a_00_7 = {63 00 64 00 5f 00 6b 00 65 00 79 00 74 00 78 00 74 00 5f 00 43 00 72 00 65 00 61 00 74 00 65 00 } //1 cd_keytxt_Create
		$a_00_8 = {50 00 61 00 73 00 73 00 77 00 6f 00 72 00 64 00 2e 00 4e 00 45 00 54 00 20 00 4d 00 65 00 73 00 73 00 65 00 6e 00 67 00 65 00 72 00 20 00 53 00 65 00 72 00 76 00 69 00 63 00 65 00 } //1 Password.NET Messenger Service
	condition:
		((#a_00_0  & 1)*2+(#a_01_1  & 1)*2+(#a_00_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_00_7  & 1)*1+(#a_00_8  & 1)*1) >=8
 
}