
rule TrojanSpy_Win32_Banker_JZ{
	meta:
		description = "TrojanSpy:Win32/Banker.JZ,SIGNATURE_TYPE_PEHSTR_EXT,18 00 18 00 06 00 00 0a 00 "
		
	strings :
		$a_01_0 = {8b 45 f8 8b 55 e4 0f b6 44 10 ff 03 c7 b9 ff 00 00 00 99 f7 f9 8b da 3b 75 f0 7d 03 46 eb 05 be 01 00 00 00 8b 45 e8 0f b6 44 30 ff 33 d8 8d 45 cc 50 89 5d d0 c6 45 d4 00 } //0a 00 
		$a_00_1 = {53 4f 46 54 57 41 52 45 5c 42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 } //03 00  SOFTWARE\Borland\Delphi
		$a_02_2 = {45 64 69 74 31 34 90 01 06 90 90 00 45 64 69 74 32 90 01 09 90 90 00 41 41 5f 64 6f 4d 53 4e 54 69 6d 65 72 90 01 07 46 6f 72 6d 43 72 65 61 74 65 90 00 } //02 00 
		$a_02_3 = {4c 6f 67 69 6e 50 72 6f 6d 70 74 90 02 3a 50 72 6f 76 69 64 65 72 90 00 } //01 00 
		$a_00_4 = {49 6e 74 65 72 6e 65 74 43 6f 6e 6e 65 63 74 41 } //01 00  InternetConnectA
		$a_00_5 = {65 73 20 64 61 20 49 6e 74 65 72 6e 65 74 2e 2e 2e } //00 00  es da Internet...
	condition:
		any of ($a_*)
 
}