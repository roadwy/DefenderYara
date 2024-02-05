
rule TrojanSpy_Win32_Banker_ALN{
	meta:
		description = "TrojanSpy:Win32/Banker.ALN,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {59 00 55 00 51 00 4c 00 32 00 33 00 4b 00 4c 00 32 00 33 00 44 00 46 00 39 00 30 00 57 00 49 00 35 00 45 00 31 00 4a 00 41 00 53 00 34 00 36 00 37 00 4e 00 4d 00 43 00 58 00 58 00 4c 00 } //01 00 
		$a_03_1 = {41 00 56 00 47 00 90 02 16 00 5c 00 41 00 56 00 41 00 53 00 54 90 00 } //01 00 
		$a_01_2 = {77 00 69 00 6e 00 6d 00 67 00 6d 00 74 00 73 00 3a 00 5c 00 5c 00 6c 00 6f 00 63 00 61 00 6c 00 68 00 6f 00 73 00 74 00 5c 00 72 00 6f 00 6f 00 74 00 5c 00 63 00 69 00 6d 00 76 00 32 00 } //01 00 
		$a_03_3 = {84 c0 74 0d 8b 45 f8 ba 90 01 04 e8 90 01 04 8d 45 ec e8 90 01 04 8d 45 ec 50 8d 4d e8 ba 90 01 04 b8 90 01 04 e8 90 01 04 8b 55 e8 58 e8 90 01 04 8b 45 ec e8 90 01 04 84 c0 74 10 8b 45 f8 ba 90 00 } //01 00 
		$a_03_4 = {84 c0 74 0d 8b 45 f8 ba 90 01 04 e8 90 01 04 8d 45 f0 e8 90 01 04 8d 45 f0 ba 90 01 04 e8 90 01 04 8b 45 f0 e8 90 01 04 84 c0 74 10 8b 45 f8 ba 90 00 } //00 00 
		$a_00_5 = {e7 48 00 } //00 00 
	condition:
		any of ($a_*)
 
}