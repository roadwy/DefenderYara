
rule TrojanDownloader_Win32_Toselos_A{
	meta:
		description = "TrojanDownloader:Win32/Toselos.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {74 58 6a 04 8b 45 fc e8 90 01 04 50 e8 90 01 04 8b 45 f4 ba 90 01 04 e8 90 01 04 75 0c 90 00 } //01 00 
		$a_01_1 = {68 74 74 70 3a 2f 2f 25 73 2f 74 6f 6f 6c 73 2e 74 78 74 } //01 00 
		$a_01_2 = {74 61 73 6b 6b 69 6c 6c 20 2f 46 20 2f 50 49 44 20 25 64 } //00 00 
	condition:
		any of ($a_*)
 
}