
rule TrojanDownloader_Win32_Jadtre_A{
	meta:
		description = "TrojanDownloader:Win32/Jadtre.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 02 00 "
		
	strings :
		$a_01_0 = {74 14 8b 45 fc 8b 00 f7 d0 8b 4d fc 03 41 04 8b 4d fc 89 01 eb } //01 00 
		$a_01_1 = {6a 04 8d 45 f4 50 68 93 21 22 00 ff 75 f8 ff 15 } //01 00 
		$a_01_2 = {c7 40 fb e9 00 00 00 8b 45 f4 03 45 f8 8b 4d fc 2b c8 8b 45 f4 03 45 f8 89 48 fc 8b 45 f4 ff e0 } //00 00 
	condition:
		any of ($a_*)
 
}