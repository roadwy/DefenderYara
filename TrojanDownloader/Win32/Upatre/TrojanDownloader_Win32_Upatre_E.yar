
rule TrojanDownloader_Win32_Upatre_E{
	meta:
		description = "TrojanDownloader:Win32/Upatre.E,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {03 45 fc 8b d8 33 c0 43 8b 0b 40 81 e1 ff 00 00 00 85 c9 75 f2 48 3b 45 ?? 75 12 8b 07 03 45 ?? ff 75 ?? 50 e8 ?? 00 00 00 85 c0 74 0e 83 c7 04 ff 45 f8 8b 45 f8 3b 45 f4 72 c2 8b 45 f8 3b 45 f4 73 1f 8b 4e 24 03 c8 03 c8 8b 45 fc 03 c8 0f b7 01 8b 4e 1c 8d 04 81 8b 4d fc 8b 04 01 03 c1 eb 02 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}