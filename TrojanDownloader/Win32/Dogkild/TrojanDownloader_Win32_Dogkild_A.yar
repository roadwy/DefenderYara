
rule TrojanDownloader_Win32_Dogkild_A{
	meta:
		description = "TrojanDownloader:Win32/Dogkild.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {5c 5c 2e 5c 70 63 69 64 75 6d 70 } //01 00 
		$a_01_1 = {6b 69 6c 6c 64 6c 6c 2e 64 6c 6c } //01 00 
		$a_03_2 = {6a 08 8d 45 f0 50 68 14 20 22 00 8b 4d f8 51 ff 15 90 01 04 89 45 fc eb 07 c7 45 fc ff ff ff ff 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}