
rule TrojanDownloader_Win32_Moure_gen_C{
	meta:
		description = "TrojanDownloader:Win32/Moure.gen!C,SIGNATURE_TYPE_PEHSTR_EXT,69 00 69 00 09 00 00 64 00 "
		
	strings :
		$a_03_0 = {ff b5 dc fe ff ff 50 6a 01 ff 15 90 01 04 8b f0 85 f6 74 90 01 01 6a 01 56 ff 15 90 01 04 56 03 d8 ff 15 90 01 04 8d 85 d4 fe ff ff 50 57 ff 15 90 01 04 85 c0 75 90 01 01 57 ff 15 90 00 } //64 00 
		$a_03_1 = {8b 5d f4 3b df 0f 86 90 01 04 b8 90 01 04 8d 50 01 8a 08 40 84 c9 75 90 01 01 2b c2 6a 06 8d 74 33 e8 83 c3 e8 8d b8 90 01 04 59 f3 a5 90 00 } //64 00 
		$a_01_2 = {3a cb 75 f9 2b c2 3b c3 74 1a 80 bc 04 97 00 00 00 5c 74 10 c6 84 04 98 00 00 00 5c 40 88 9c 04 98 } //64 00 
		$a_01_3 = {33 c0 ac 3c 61 7c 02 2c 20 c1 cf 0d 03 f8 e2 f0 81 ff 5b bc 4a 6a 8b 5a 10 8b 12 } //01 00 
		$a_81_4 = {00 4d 53 41 53 43 75 69 2e 65 78 65 00 } //01 00 
		$a_81_5 = {00 4d 70 43 6d 64 52 75 6e 2e 65 78 65 00 } //01 00 
		$a_81_6 = {00 4d 73 4d 70 45 6e 67 2e 65 78 65 00 } //01 00 
		$a_81_7 = {00 4e 69 73 53 72 76 2e 65 78 65 00 } //01 00 
		$a_81_8 = {00 6d 73 73 65 63 65 73 2e 65 78 65 00 } //00 00 
	condition:
		any of ($a_*)
 
}