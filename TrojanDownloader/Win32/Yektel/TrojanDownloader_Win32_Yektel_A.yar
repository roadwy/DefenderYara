
rule TrojanDownloader_Win32_Yektel_A{
	meta:
		description = "TrojanDownloader:Win32/Yektel.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {47 66 81 ff 28 23 7d 52 33 c0 89 04 24 54 6a 00 55 e8 90 01 02 ff ff e8 90 01 02 ff ff 90 00 } //01 00 
		$a_03_1 = {66 3d 19 04 74 06 66 3d 22 04 75 90 01 01 a1 90 01 04 8b 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}