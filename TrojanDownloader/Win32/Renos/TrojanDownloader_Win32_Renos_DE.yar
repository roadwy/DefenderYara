
rule TrojanDownloader_Win32_Renos_DE{
	meta:
		description = "TrojanDownloader:Win32/Renos.DE,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 03 00 "
		
	strings :
		$a_03_0 = {89 5d f4 53 eb 3d 83 7d ec 01 75 16 68 90 01 04 8d 85 e8 fe ff ff 50 ff 15 90 01 04 85 c0 74 32 ff 45 f4 90 00 } //02 00 
		$a_03_1 = {8b f0 6a 11 c1 e6 02 ff b6 90 01 04 ff b6 90 01 04 6a 00 ff 15 90 01 04 83 f8 01 75 19 6a 05 90 00 } //01 00 
		$a_01_2 = {73 70 79 77 61 72 65 77 61 72 6e 69 6e 67 2e 6d 68 74 00 } //01 00 
		$a_01_3 = {73 70 79 77 61 72 65 77 61 72 6e 69 6e 67 32 2e 6d 68 74 00 } //00 00  灳睹牡睥牡楮杮⸲桭t
	condition:
		any of ($a_*)
 
}