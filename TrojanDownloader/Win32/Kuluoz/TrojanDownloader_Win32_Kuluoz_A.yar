
rule TrojanDownloader_Win32_Kuluoz_A{
	meta:
		description = "TrojanDownloader:Win32/Kuluoz.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {89 45 fc c6 85 90 01 02 ff ff 25 c6 85 90 01 02 ff ff 2e c6 85 90 01 02 ff ff 38 c6 85 90 01 02 ff ff 78 c6 85 90 01 02 ff ff 00 90 00 } //01 00 
		$a_03_1 = {83 c4 08 c6 45 90 01 01 2e c6 45 90 01 01 65 c6 45 90 01 01 78 c6 45 90 01 01 65 c6 45 90 01 01 00 8d 4d 90 1b 00 51 8b 55 90 01 01 52 ff 55 90 00 } //01 00 
		$a_03_2 = {c6 40 01 68 8b 8d 90 01 02 ff ff 03 8d 90 01 02 ff ff 8b 55 90 01 01 89 51 02 8b 85 90 1b 00 ff ff 03 85 90 1b 01 ff ff c6 40 06 c3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}