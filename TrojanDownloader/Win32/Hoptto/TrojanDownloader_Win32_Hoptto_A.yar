
rule TrojanDownloader_Win32_Hoptto_A{
	meta:
		description = "TrojanDownloader:Win32/Hoptto.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {68 60 ea 00 00 e8 90 01 04 ff 35 90 01 04 e8 90 01 04 e9 90 01 04 68 00 00 00 00 e8 90 01 04 ff 35 90 01 04 e8 90 00 } //01 00 
		$a_03_1 = {c7 44 24 08 01 00 00 80 ba 90 01 04 8d 4c 24 0c e8 90 01 04 8d 44 24 10 50 8b 44 24 10 50 ff 74 24 10 e8 90 01 04 ff 74 24 04 90 00 } //01 00 
		$a_03_2 = {89 c3 81 c3 10 27 00 00 89 1c 24 ff 35 90 01 04 68 00 00 00 00 68 00 00 00 00 90 02 80 8b 6c 24 20 ff 75 00 68 00 00 00 00 8b 15 90 01 03 00 01 54 24 08 e8 90 00 } //01 00 
		$a_01_3 = {70 75 72 65 6e 65 74 2e 68 6f 70 74 6f 2e 6f 72 67 00 } //00 00 
	condition:
		any of ($a_*)
 
}