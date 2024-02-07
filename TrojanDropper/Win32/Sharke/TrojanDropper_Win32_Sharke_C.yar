
rule TrojanDropper_Win32_Sharke_C{
	meta:
		description = "TrojanDropper:Win32/Sharke.C,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_00_0 = {81 fe 04 01 00 00 73 1d 32 c9 85 f6 76 17 33 c0 8a d1 80 c2 02 30 90 00 01 42 00 80 c1 01 0f b6 c1 3b c6 72 eb } //01 00 
		$a_02_1 = {50 8d 4c 24 90 01 01 51 6a 00 6a 00 6a 04 6a 00 6a 00 6a 00 68 90 01 03 00 6a 00 c7 44 24 90 01 01 44 00 00 00 ff 15 90 01 03 00 8b 90 02 08 8d 54 24 90 01 01 52 50 ff 15 90 01 03 00 8b 84 24 90 01 04 8d 4c 24 90 01 01 51 8b 90 02 08 6a 04 8d 54 24 1c 52 83 c0 08 50 51 ff 15 90 01 03 00 68 90 01 04 68 90 01 04 ff 15 90 01 03 00 50 90 00 } //01 00 
		$a_01_2 = {5a 77 55 6e 6d 61 70 56 69 65 77 4f 66 53 65 63 74 69 6f 6e } //01 00  ZwUnmapViewOfSection
		$a_01_3 = {69 66 76 6b 63 6b 3b 3b 24 6f 60 61 } //01 00  ifvkck;;$o`a
		$a_01_4 = {77 70 61 77 35 35 26 6d 66 67 } //01 00  wpaw55&mfg
		$a_01_5 = {63 67 72 64 76 6e 3b 3b 24 6f 60 61 } //01 00  cgrdvn;;$o`a
		$a_01_6 = {75 6a 6a 6c 68 62 7c 27 6e 67 60 } //00 00  ujjlhb|'ng`
	condition:
		any of ($a_*)
 
}
rule TrojanDropper_Win32_Sharke_C_2{
	meta:
		description = "TrojanDropper:Win32/Sharke.C,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_02_0 = {55 8b ec 33 c9 51 51 51 51 51 51 51 53 56 57 8b 75 10 33 c0 55 68 90 01 04 64 ff 30 64 89 20 b8 05 01 00 00 e8 d2 d8 ff ff 8b d8 68 04 01 00 00 53 e8 90 01 04 68 04 01 00 00 53 e8 90 01 04 8b c3 e8 97 d8 ff ff 8b d0 8d 45 f4 e8 65 ba ff ff c7 45 fc ff ff ff ff 8b 45 0c 50 56 6a 00 e8 90 01 04 8b d8 6a 00 68 80 00 00 00 6a 02 6a 00 6a 02 68 00 00 00 40 ff 75 f4 68 90 01 04 8d 45 ec 8b d6 e8 2c ba ff ff ff 75 ec 8d 45 f0 ba 03 00 00 00 e8 00 bb ff ff 8b 45 f0 e8 84 bb ff ff 50 e8 90 01 04 8b f8 6a 00 8d 45 f8 50 53 6a 00 e8 90 01 04 50 53 6a 00 e8 90 01 04 50 e8 90 01 04 50 57 e8 90 01 04 57 e8 90 01 04 6a 01 6a 00 6a 00 ff 75 f4 68 90 00 } //01 00 
		$a_01_1 = {5c 48 65 6c 70 5c 00 00 4f 50 45 4e } //01 00 
		$a_01_2 = {46 69 6e 64 52 65 73 6f 75 72 63 65 41 } //01 00  FindResourceA
		$a_01_3 = {45 6e 75 6d 52 65 73 6f 75 72 63 65 4e 61 6d 65 73 41 } //01 00  EnumResourceNamesA
		$a_01_4 = {53 68 65 6c 6c 45 78 65 63 75 74 65 41 } //00 00  ShellExecuteA
	condition:
		any of ($a_*)
 
}