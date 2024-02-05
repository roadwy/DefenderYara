
rule TrojanDownloader_Win32_Enstan_A{
	meta:
		description = "TrojanDownloader:Win32/Enstan.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 00 3c 00 74 90 01 01 c1 0d 90 01 02 40 00 0d 90 00 } //01 00 
		$a_03_1 = {68 c7 69 9b fa 68 90 01 02 40 00 e8 90 01 02 ff ff 90 00 } //01 00 
		$a_03_2 = {68 66 57 38 ef 68 90 01 02 40 00 e8 90 01 02 ff ff 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}