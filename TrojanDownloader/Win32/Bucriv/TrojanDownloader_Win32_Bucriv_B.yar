
rule TrojanDownloader_Win32_Bucriv_B{
	meta:
		description = "TrojanDownloader:Win32/Bucriv.B,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {03 f0 80 7d 90 01 01 c3 74 90 01 01 80 7d 90 01 01 c2 74 90 01 01 8d 45 90 01 01 50 8d 04 3e 50 e8 90 00 } //01 00 
		$a_03_1 = {6a 00 ff 75 f0 ff 75 08 ff 55 f4 85 c0 90 03 07 04 0f 8d 90 01 02 ff ff 7d 90 01 01 ff 75 1c ff 75 18 ff 75 14 ff 75 10 ff 75 f0 ff 75 08 ff 55 f4 89 45 0c 61 9d 8b 45 0c 8b e5 5d c2 18 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}