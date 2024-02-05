
rule TrojanDownloader_Win32_Renos_JF{
	meta:
		description = "TrojanDownloader:Win32/Renos.JF,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 07 00 00 02 00 "
		
	strings :
		$a_03_0 = {8a 00 3c 21 0f 84 90 01 02 00 00 3c 2c 74 0a 3c 3b 0f 84 90 00 } //02 00 
		$a_03_1 = {8a 09 80 f9 21 0f 84 90 01 02 00 00 80 f9 2c 74 0b 80 f9 3b 0f 84 90 00 } //01 00 
		$a_03_2 = {6a 04 50 56 89 5d 90 01 01 89 5d 90 01 01 ff 15 90 01 04 85 c0 74 90 01 01 83 7d 90 01 01 04 75 90 00 } //01 00 
		$a_03_3 = {88 04 0a 74 06 41 80 39 00 75 f1 90 09 04 00 8a 01 34 90 00 } //01 00 
		$a_01_4 = {2c 21 3b 00 fe 00 00 00 } //01 00 
		$a_01_5 = {91 e7 bf 92 00 } //01 00 
		$a_03_6 = {ff 45 f4 8b 73 04 83 c3 04 89 07 83 c7 04 ff 45 fc 85 f6 75 90 01 01 83 45 f8 04 ff 45 fc 81 7d f8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}