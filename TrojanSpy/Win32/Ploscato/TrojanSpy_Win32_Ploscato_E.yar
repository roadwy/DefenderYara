
rule TrojanSpy_Win32_Ploscato_E{
	meta:
		description = "TrojanSpy:Win32/Ploscato.E,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {2e 6d 65 6d 64 75 6d 70 00 } //01 00 
		$a_01_1 = {4b 41 50 54 4f 58 41 00 } //01 00  䅋呐塏A
		$a_01_2 = {47 4f 54 49 54 20 00 } //01 00 
		$a_01_3 = {50 4f 53 57 44 53 00 } //01 00 
		$a_01_4 = {4d 6d 6f 6e 4e 65 77 5c 44 65 62 75 67 5c 6d 6d 6f 6e 2e 70 64 62 00 } //01 00 
		$a_01_5 = {73 4e 62 72 6c 53 66 79 42 4d 32 50 52 35 37 54 71 33 51 65 56 70 6e 57 34 2b 77 38 4a 4f 48 4b 36 43 6f 67 75 59 78 76 6b 2f 49 64 5a 30 4c 58 6a 55 61 41 68 47 7a 44 46 6d 63 74 39 45 69 31 00 } //00 00 
	condition:
		any of ($a_*)
 
}