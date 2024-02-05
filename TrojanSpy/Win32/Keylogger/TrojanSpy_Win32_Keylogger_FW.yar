
rule TrojanSpy_Win32_Keylogger_FW{
	meta:
		description = "TrojanSpy:Win32/Keylogger.FW,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {50 52 49 4e 54 2d 53 43 52 45 45 4e 7d } //01 00 
		$a_01_1 = {c6 45 d7 67 c6 45 d8 50 c6 45 d9 72 c6 45 da 69 c6 45 db 76 c6 45 dc 2e 88 5d dd c6 45 de 78 } //01 00 
		$a_01_2 = {c6 45 a6 63 c6 45 a7 75 c6 45 a8 72 c6 45 a9 69 c6 45 aa 74 c6 45 ab 79 c6 45 ad 54 } //01 00 
		$a_01_3 = {c6 45 c4 44 c6 45 c5 69 c6 45 c6 73 88 5d c7 c6 45 c8 62 88 55 ca c6 45 cb 54 c6 45 cc 68 } //01 00 
		$a_01_4 = {c6 44 24 0c 75 c6 44 24 0f 72 c6 44 24 10 33 c6 44 24 11 32 c6 44 24 12 2e c6 44 24 13 64 } //00 00 
	condition:
		any of ($a_*)
 
}