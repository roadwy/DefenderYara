
rule TrojanSpy_Win32_QQspy_A{
	meta:
		description = "TrojanSpy:Win32/QQspy.A,SIGNATURE_TYPE_PEHSTR_EXT,06 00 05 00 07 00 00 01 00 "
		
	strings :
		$a_00_0 = {53 4f 46 54 57 41 52 45 5c 42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 } //01 00  SOFTWARE\Borland\Delphi
		$a_01_1 = {68 75 75 70 3a 2f 2f 31 30 2e 31 2e 32 35 34 2e 32 33 33 2f 69 6e 64 65 78 2e 61 73 70 2a } //01 00  huup://10.1.254.233/index.asp*
		$a_01_2 = {54 45 4e 43 45 4e 54 00 } //01 00  䕔䍎久T
		$a_03_3 = {35 ae ca 7b c3 ff 25 90 01 04 8b c0 53 33 db 6a 00 e8 ee ff ff ff 83 f8 07 75 1c 90 00 } //01 00 
		$a_01_4 = {0f b6 08 88 0a c3 0f b7 08 66 89 0a c3 } //01 00 
		$a_03_5 = {4c 6f 63 61 6c 50 6f 72 74 00 90 01 09 00 36 36 35 30 30 00 90 00 } //01 00 
		$a_01_6 = {68 74 74 70 3a 2f 2f 31 30 2e 31 2e 32 35 34 2e 32 33 33 2f 64 6f 77 6e 2e 74 78 74 00 } //00 00 
	condition:
		any of ($a_*)
 
}