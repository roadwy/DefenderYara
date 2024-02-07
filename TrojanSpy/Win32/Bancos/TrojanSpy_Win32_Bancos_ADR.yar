
rule TrojanSpy_Win32_Bancos_ADR{
	meta:
		description = "TrojanSpy:Win32/Bancos.ADR,SIGNATURE_TYPE_PEHSTR_EXT,06 00 05 00 08 00 00 01 00 "
		
	strings :
		$a_00_0 = {53 79 73 74 65 6d 33 32 5c 72 65 67 2e 65 78 65 20 41 44 44 20 48 4b 4c 4d 5c 53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 50 6f 6c 69 63 69 65 73 5c 53 79 73 74 65 6d 20 2f 76 20 20 45 6e 61 62 6c 65 4c 55 41 20 2f 74 20 52 45 47 5f 44 57 4f 52 44 20 2f 64 20 30 20 2f 66 } //01 00  System32\reg.exe ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v  EnableLUA /t REG_DWORD /d 0 /f
		$a_01_1 = {77 69 6e 64 6f 77 73 3d 24 5f 00 } //01 00 
		$a_00_2 = {29 20 47 65 63 6b 6f 2f 32 30 30 39 30 38 32 34 20 46 69 72 65 66 6f 78 2f } //01 00  ) Gecko/20090824 Firefox/
		$a_01_3 = {57 69 6e 64 6f 77 73 56 69 73 74 61 2f 37 00 } //01 00 
		$a_01_4 = {8b 37 85 db 74 15 8a 02 3c 61 72 06 3c 7a 77 02 2c 20 88 06 42 46 4b } //01 00 
		$a_03_5 = {83 f8 05 75 90 01 01 85 d2 75 90 01 01 8b c3 ba 90 01 04 e8 90 01 04 e9 90 01 04 83 f8 05 75 90 01 01 4a 75 90 01 01 8b c3 ba 90 01 04 e8 90 01 04 eb 90 01 01 83 f8 06 75 90 00 } //01 00 
		$a_00_6 = {ff 51 74 6a 00 6a 00 6a 00 8d 4d e4 ba b8 d9 45 00 b8 5c d9 45 00 e8 01 02 ff ff 90 00 } //01 00 
		$a_02_7 = {66 81 38 4d 5a 75 90 01 01 60 89 85 90 01 04 8b d0 8b d8 03 40 3c 03 58 78 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}