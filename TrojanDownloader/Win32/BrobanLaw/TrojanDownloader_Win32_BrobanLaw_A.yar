
rule TrojanDownloader_Win32_BrobanLaw_A{
	meta:
		description = "TrojanDownloader:Win32/BrobanLaw.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {c7 45 f4 01 00 00 00 8b 45 fc 8b 55 f4 33 db 8a 5c 10 ff 03 5d f8 8b c3 33 d2 52 50 8d 45 e8 e8 90 01 04 8b 45 e8 e8 90 00 } //01 00 
		$a_03_1 = {64 ff 35 00 00 00 00 64 89 25 00 00 00 00 58 c3 e9 90 09 05 00 68 90 00 } //01 00 
		$a_03_2 = {2e 63 61 62 00 00 ff ff ff ff 0a 00 00 00 90 01 06 2e 63 61 62 90 00 } //00 00 
		$a_00_3 = {78 7c } //00 00 
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_Win32_BrobanLaw_A_2{
	meta:
		description = "TrojanDownloader:Win32/BrobanLaw.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {3b c3 7d 05 bb 01 00 00 00 8b 45 90 01 01 0f b7 44 90 01 02 8b 55 90 01 01 0f b7 54 90 01 02 66 33 c2 0f b7 c0 90 00 } //01 00 
		$a_03_1 = {3d b7 00 00 00 74 4c e8 90 01 04 b8 90 01 04 e8 90 01 04 05 90 01 04 50 e8 90 01 04 e8 90 01 04 8b d0 b8 90 01 04 e8 90 01 04 6a 24 68 90 01 04 68 90 01 04 e8 90 01 04 50 e8 90 01 04 83 f8 06 75 05 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_Win32_BrobanLaw_A_3{
	meta:
		description = "TrojanDownloader:Win32/BrobanLaw.A,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 05 00 00 0a 00 "
		
	strings :
		$a_01_0 = {53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 66 00 67 00 69 00 75 00 73 00 6a 00 69 00 } //01 00 
		$a_03_1 = {69 00 65 00 78 00 70 00 6c 00 6f 00 72 00 65 00 2e 00 65 00 78 00 65 00 90 01 10 90 02 10 77 00 6d 00 70 00 6c 00 61 00 79 00 65 00 72 00 2e 00 65 00 78 00 65 00 90 00 } //01 00 
		$a_03_2 = {69 00 65 00 78 00 70 00 6c 00 6f 00 72 00 65 00 2e 00 65 00 78 00 65 00 90 01 10 90 02 10 69 00 65 00 69 00 6e 00 73 00 74 00 61 00 6c 00 2e 00 65 00 78 00 65 00 90 00 } //01 00 
		$a_03_3 = {77 00 6d 00 70 00 6c 00 61 00 79 00 65 00 72 00 2e 00 65 00 78 00 65 00 90 01 10 90 02 40 69 00 65 00 78 00 70 00 6c 00 6f 00 72 00 65 00 2e 00 65 00 78 00 65 00 90 00 } //01 00 
		$a_03_4 = {77 00 6d 00 70 00 6c 00 61 00 79 00 65 00 72 00 2e 00 65 00 78 00 65 90 09 20 00 6f 90 01 0f 5c 90 00 } //00 00 
		$a_00_5 = {7e 15 00 00 77 02 e2 ad 70 ca } //84 4d 
	condition:
		any of ($a_*)
 
}