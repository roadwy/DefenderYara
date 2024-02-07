
rule TrojanDownloader_Win32_Banload_gen_X{
	meta:
		description = "TrojanDownloader:Win32/Banload.gen!X,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 07 00 00 0a 00 "
		
	strings :
		$a_01_0 = {8a 5c 38 ff 33 5d e4 3b 5d f0 7f 0b 81 c3 ff 00 00 00 2b 5d f0 eb 03 2b 5d f0 8d 45 d4 8b d3 e8 } //01 00 
		$a_03_1 = {2f 30 31 2f 00 00 00 00 ff ff ff ff 90 09 04 00 04 90 00 } //01 00 
		$a_03_2 = {2f 30 31 00 ff ff ff ff 90 09 04 00 03 90 00 } //01 00 
		$a_01_3 = {74 6d 72 49 6e 69 63 69 61 6c 54 69 6d 65 72 } //01 00  tmrInicialTimer
		$a_01_4 = {74 6d 72 62 66 31 54 69 6d 65 72 } //01 00  tmrbf1Timer
		$a_01_5 = {54 66 6f 72 6d 63 64 78 } //01 00  Tformcdx
		$a_03_6 = {83 c4 f8 dd 1c 24 9b 8d 90 09 1c 00 b8 90 01 04 e8 90 01 04 8d 90 01 02 ba 90 01 04 e8 90 01 04 e8 90 00 } //00 00 
		$a_00_7 = {80 10 00 00 f2 af e5 29 5e 05 } //ff da 
	condition:
		any of ($a_*)
 
}