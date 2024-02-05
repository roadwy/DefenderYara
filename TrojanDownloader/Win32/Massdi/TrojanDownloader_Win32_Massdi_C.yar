
rule TrojanDownloader_Win32_Massdi_C{
	meta:
		description = "TrojanDownloader:Win32/Massdi.C,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 3a 2f 2f 77 77 77 31 2e 65 2d 73 6f 73 6f 2e 63 6f 6d 2f 70 6f 70 2f 67 75 61 67 75 61 2e 65 78 65 00 } //01 00 
		$a_03_1 = {68 74 74 70 3a 2f 2f 77 77 77 31 2e 65 2d 73 6f 73 6f 2e 63 6f 6d 2f 74 6a 2f 54 4a 90 02 05 2e 65 78 65 90 00 } //01 00 
		$a_01_2 = {5b 41 62 6f 72 74 5d 20 b7 c5 c6 fa b0 b2 d7 b0 a3 ac 0d 0a 20 5b 52 65 74 72 79 5d 20 d6 d8 d0 c2 b3 a2 ca d4 d0 b4 c8 eb ce c4 bc fc fe a3 ac bb f2 0d 0a 20 5b 49 67 6e 6f 72 65 5d 20 ba f6 c2 d4 d5 e2 } //00 00 
	condition:
		any of ($a_*)
 
}