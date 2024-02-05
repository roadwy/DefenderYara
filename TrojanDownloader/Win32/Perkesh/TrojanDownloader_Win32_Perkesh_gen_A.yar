
rule TrojanDownloader_Win32_Perkesh_gen_A{
	meta:
		description = "TrojanDownloader:Win32/Perkesh.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 08 00 00 02 00 "
		
	strings :
		$a_03_0 = {76 10 8a 14 0e 80 f2 90 01 01 f6 d2 88 14 0e 46 3b f0 72 f0 90 00 } //02 00 
		$a_01_1 = {c6 40 ff 74 c6 40 fe 78 c6 40 fd 74 } //01 00 
		$a_01_2 = {68 20 24 08 00 ff 75 08 ff 15 } //01 00 
		$a_01_3 = {83 c7 04 8b 07 3b c6 75 c2 68 e8 03 00 00 ff 55 f4 eb a7 } //01 00 
		$a_01_4 = {44 6f 77 6e 44 6c 6c 2e 64 6c 6c 00 53 65 72 76 } //02 00 
		$a_03_5 = {81 7d 0c 01 04 00 00 74 90 01 01 81 7d 0c 00 04 00 00 74 90 01 10 90 02 10 b8 22 00 00 c0 90 00 } //01 00 
		$a_03_6 = {81 e9 18 24 08 00 0f 84 90 01 0d 81 e9 e0 ff 19 00 90 00 } //03 00 
		$a_03_7 = {40 83 f8 09 72 ef 90 09 0b 00 8a 4c 05 90 01 01 80 f1 90 01 01 88 4c 05 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}