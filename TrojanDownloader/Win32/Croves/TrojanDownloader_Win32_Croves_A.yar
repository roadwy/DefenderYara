
rule TrojanDownloader_Win32_Croves_A{
	meta:
		description = "TrojanDownloader:Win32/Croves.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {c7 45 fc 10 00 00 00 c7 85 90 01 04 04 00 00 00 8d 45 90 01 01 50 8d 85 90 01 04 50 8b 45 08 05 90 01 04 50 8d 45 90 01 01 50 8b 45 08 8b 00 ff 75 08 ff 50 30 89 85 90 01 04 83 bd 90 01 04 00 7d 90 00 } //01 00 
		$a_03_1 = {8b 00 ff b5 90 01 04 ff 50 40 db e2 89 85 90 01 04 83 bd 90 01 04 00 7d 20 6a 40 68 90 01 04 ff b5 90 01 04 ff b5 90 01 04 e8 90 01 04 89 85 90 01 04 eb 07 83 a5 90 01 04 00 8b 45 90 01 01 89 85 90 01 04 83 65 90 01 01 00 8b 95 90 01 04 b9 90 01 04 e8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}