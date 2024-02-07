
rule TrojanDownloader_Win32_Renos_AW{
	meta:
		description = "TrojanDownloader:Win32/Renos.AW,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {68 69 2c 20 62 6f 74 6e 65 74 20 4a 61 63 6b 20 68 65 72 65 } //01 00  hi, botnet Jack here
		$a_01_1 = {72 69 6f 2e 64 6c 6c 00 44 6c 6c 4d 61 69 6e 00 57 4c 45 76 65 6e 74 53 74 61 72 74 53 68 65 6c 6c } //00 00 
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_Win32_Renos_AW_2{
	meta:
		description = "TrojanDownloader:Win32/Renos.AW,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {83 7d fc 02 7e 23 8b 45 fc 83 e8 02 83 e0 01 85 c0 75 16 8b 45 fc 8b 4d 08 01 c1 8b 45 fc 8b 55 08 01 c2 b0 90 01 01 02 02 88 01 90 00 } //01 00 
		$a_01_1 = {68 69 2c 20 62 6f 74 6e 65 74 20 4a 61 63 6b 20 68 65 72 65 } //00 00  hi, botnet Jack here
	condition:
		any of ($a_*)
 
}