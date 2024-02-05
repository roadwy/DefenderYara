
rule TrojanDownloader_Win32_Cratorr_gen_A{
	meta:
		description = "TrojanDownloader:Win32/Cratorr.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 05 00 00 03 00 "
		
	strings :
		$a_03_0 = {83 65 fc 00 8b 75 08 6a 04 bf 90 01 04 59 33 c0 f3 a6 74 05 1b c0 83 d8 ff 85 c0 75 07 b8 90 01 04 eb 43 8b 75 08 6a 09 90 00 } //01 00 
		$a_01_1 = {46 49 4c 45 30 3d 22 63 72 61 63 6b 2e 65 78 65 } //01 00 
		$a_01_2 = {2f 63 72 61 63 6b 2f 28 5c 64 2b 29 2f 22 3e 28 5b 5e 3c 5d 2b 29 3c 2f 61 3e 00 } //01 00 
		$a_01_3 = {31 30 3a 63 72 65 61 74 65 64 20 62 79 } //01 00 
		$a_01_4 = {37 3a 63 6f 6d 6d 65 6e 74 25 64 3a 25 73 00 } //00 00 
	condition:
		any of ($a_*)
 
}