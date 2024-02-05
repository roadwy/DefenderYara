
rule TrojanDownloader_Win32_Renos_IT{
	meta:
		description = "TrojanDownloader:Win32/Renos.IT,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {88 04 3e 46 eb 90 09 05 00 35 90 01 01 00 00 00 90 00 } //01 00 
		$a_01_1 = {68 ff ff 0d ba ff 15 } //00 00 
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_Win32_Renos_IT_2{
	meta:
		description = "TrojanDownloader:Win32/Renos.IT,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 02 66 2b c0 c1 c2 19 b9 08 ef bf ff f7 d1 e8 } //01 00 
		$a_01_1 = {8b 39 c1 f2 15 66 83 c1 33 83 c0 01 c1 c6 09 8b 08 f7 d2 29 f9 75 ee } //00 00 
	condition:
		any of ($a_*)
 
}