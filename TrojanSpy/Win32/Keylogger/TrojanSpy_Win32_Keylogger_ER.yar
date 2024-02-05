
rule TrojanSpy_Win32_Keylogger_ER{
	meta:
		description = "TrojanSpy:Win32/Keylogger.ER,SIGNATURE_TYPE_PEHSTR,18 00 18 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {5c 77 69 6e 64 6f 77 73 5c 6c 73 61 73 73 2e 65 78 65 } //01 00 
		$a_01_1 = {5c 77 69 6e 64 6f 77 73 5c 73 65 72 76 69 63 65 73 2e 69 6e 69 } //01 00 
		$a_01_2 = {4b 6f 70 61 74 68 } //01 00 
		$a_01_3 = {4b 6e 69 67 68 74 4f 6e 6c 69 6e 65 } //0a 00 
		$a_01_4 = {6a 00 68 34 e3 45 00 68 34 e3 45 00 8d 45 d8 ba dc 6c 46 00 b9 91 00 00 00 e8 98 69 fa ff 8d 45 d8 ba 40 e3 45 00 e8 e7 69 fa ff 8b 45 d8 e8 a3 6b fa ff 50 68 54 e3 45 00 6a 00 e8 32 9a fc ff } //0a 00 
		$a_01_5 = {b9 6c df 45 00 ba 7c df 45 00 8b c3 8b 30 ff 56 04 8b c3 e8 7d 5c fa ff 6a ff 8d 45 e8 ba dc 6c 46 00 b9 91 00 00 00 e8 ed 6c fa ff 8d 45 e8 ba 94 df 45 00 e8 3c 6d fa ff 8b 45 e8 e8 f8 6e fa ff 50 68 ac df 45 00 e8 c1 89 fa ff b8 54 df 45 00 e8 e3 6e fa ff 50 e8 d9 89 fa ff } //00 00 
	condition:
		any of ($a_*)
 
}