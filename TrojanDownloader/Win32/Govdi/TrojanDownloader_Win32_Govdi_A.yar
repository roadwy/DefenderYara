
rule TrojanDownloader_Win32_Govdi_A{
	meta:
		description = "TrojanDownloader:Win32/Govdi.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {2a c1 c0 e0 02 88 04 2b 0f be 54 3e 01 52 51 ff 15 40 30 40 00 8a 14 2b 2d 90 01 04 8b c8 c1 f9 04 0a d1 c0 e0 04 88 14 2b 88 44 2b 01 0f be 54 3e 02 90 00 } //01 00 
		$a_03_1 = {8b d8 83 c4 08 85 db 75 0b 5f 5e 5d 5b 81 c4 90 01 02 00 00 c3 8b 3d 90 01 04 6a 02 6a fa 53 ff d7 90 09 1a 00 c6 44 24 90 01 01 ff c6 44 24 90 01 01 02 c6 44 24 90 01 01 b7 c6 44 24 90 01 01 bc ff 15 90 00 } //01 00 
		$a_03_2 = {51 c6 44 24 90 01 01 69 c6 44 24 90 01 01 6e c6 44 24 90 01 01 45 c6 44 24 90 01 01 78 c6 44 24 90 01 01 65 c6 44 24 90 01 01 63 c6 44 24 90 01 01 00 ff d7 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}