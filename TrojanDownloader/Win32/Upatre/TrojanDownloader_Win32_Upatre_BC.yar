
rule TrojanDownloader_Win32_Upatre_BC{
	meta:
		description = "TrojanDownloader:Win32/Upatre.BC,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 0e 00 00 02 00 "
		
	strings :
		$a_01_0 = {66 ad 03 c3 ab 33 c0 e2 f7 b8 04 00 00 00 6a 04 68 00 10 00 00 68 00 00 aa 00 51 ff 93 28 11 00 00 } //02 00 
		$a_01_1 = {ac 3c 39 77 0c 3c 2e 72 08 fe c0 04 13 66 ab e2 ef } //02 00 
		$a_01_2 = {53 8b 5c 24 08 33 c0 c1 c0 07 32 03 43 80 3b 00 75 f5 5b } //02 00 
		$a_03_3 = {5b 83 c3 09 e9 90 01 04 4c 6f 61 64 4c 90 00 } //02 00 
		$a_01_4 = {51 33 c9 fc ad ab 8b c1 fc 66 ad 66 ab 8b c1 fc ac 66 ab 59 e2 ea } //02 00 
		$a_01_5 = {b0 25 66 ab b0 75 66 ab b0 00 66 ab } //02 00 
		$a_03_6 = {05 80 84 1e 00 89 45 90 01 01 05 80 8d 5b 00 89 45 90 01 01 b9 00 10 00 00 90 00 } //02 00 
		$a_01_7 = {66 ad 66 85 c0 74 f9 83 c4 0c 8b fe eb 1e 3c 00 75 b2 fe c0 04 2e fe c0 66 ab 8b 45 cc 33 c9 8b f0 41 eb 85 } //02 00 
		$a_01_8 = {04 31 50 b0 2d 66 ab b0 53 66 ab b0 50 66 ab 58 48 66 ab } //01 00 
		$a_00_9 = {25 73 25 73 00 25 73 5c 25 73 00 6f 70 65 6e } //01 00 
		$a_00_10 = {00 74 65 78 74 2f 2a 00 } //01 00  琀硥⽴*
		$a_00_11 = {00 61 70 70 6c 69 63 61 74 69 6f 6e 2f 2a 00 } //01 00 
		$a_00_12 = {63 68 65 63 6b 69 70 2e 64 79 6e 64 6e 73 2e 6f 72 67 } //01 00  checkip.dyndns.org
		$a_00_13 = {72 74 6c 64 65 63 6f 6d 70 72 65 73 73 62 75 66 66 65 72 } //00 00  rtldecompressbuffer
	condition:
		any of ($a_*)
 
}