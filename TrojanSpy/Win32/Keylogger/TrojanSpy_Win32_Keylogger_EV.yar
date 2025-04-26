
rule TrojanSpy_Win32_Keylogger_EV{
	meta:
		description = "TrojanSpy:Win32/Keylogger.EV,SIGNATURE_TYPE_PEHSTR_EXT,1a 00 1a 00 05 00 00 "
		
	strings :
		$a_00_0 = {54 43 6c 69 65 6e 74 53 6f 63 6b 65 74 } //1 TClientSocket
		$a_00_1 = {ff ff ff ff 0a 00 00 00 5b 43 41 50 53 4c 4f 43 4b 5d 00 00 ff ff ff ff 05 00 00 00 5b 45 53 43 5d } //5
		$a_00_2 = {43 3a 5c 64 6c 6c 73 65 72 77 2e 64 6c 6c 00 00 26 00 00 00 01 00 00 00 14 00 00 00 43 3a 5c 57 49 4e 44 4f 57 53 5c 73 66 64 6c 6c 2e 64 6c 6c } //5
		$a_02_3 = {48 45 4c 4f [0-38] 41 55 54 48 20 4c 4f 47 49 4e 0d 0a 00 00 00 00 ff ff ff ff 0c 00 00 00 4d 41 49 4c 20 46 52 4f 4d 3a 20 3c 00 00 00 00 ff ff ff ff 01 00 00 00 3e 00 00 00 ff ff ff ff 0a 00 00 00 52 43 50 54 20 54 4f 3a 20 3c } //5
		$a_00_4 = {53 e8 23 a6 ff ff 66 3d 01 80 0f 85 72 08 00 00 8b c3 83 c0 f8 3d d6 00 00 00 0f 87 62 08 00 00 8a 80 68 a8 40 00 ff 24 85 3f a9 40 00 } //10
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*5+(#a_00_2  & 1)*5+(#a_02_3  & 1)*5+(#a_00_4  & 1)*10) >=26
 
}