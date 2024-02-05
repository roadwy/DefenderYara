
rule TrojanDownloader_Win32_Bradop_A{
	meta:
		description = "TrojanDownloader:Win32/Bradop.A,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 04 00 00 0a 00 "
		
	strings :
		$a_03_0 = {ff b9 01 04 00 00 e8 90 01 03 ff 8b 85 f0 f9 ff ff b9 0f 00 00 00 33 d2 e8 90 01 03 ff 8b 85 f4 f9 ff ff 50 b8 90 01 04 8d 95 ec f9 ff ff e8 90 01 03 ff 8b 95 ec f9 ff ff 90 00 } //0a 00 
		$a_03_1 = {ff b9 01 04 00 00 e8 90 01 03 ff 8b 85 00 fa ff ff b9 0f 00 00 00 33 d2 e8 90 01 03 ff 8b 85 04 fa ff ff 50 8d 95 fc f9 ff ff b8 90 01 04 e8 90 01 03 ff 8b 95 fc f9 ff ff 90 00 } //01 00 
		$a_00_2 = {08 00 48 00 54 00 4d 00 4c 00 46 00 49 00 4c 00 45 00 06 00 58 00 57 00 52 00 45 00 47 00 43 00 } //09 00 
		$a_02_3 = {70 46 3a 46 2f 46 2f 90 02 02 32 90 02 02 30 90 02 02 30 90 02 02 2e 90 02 02 39 90 02 02 38 90 02 02 2e 90 02 02 31 90 02 02 33 90 02 02 36 90 02 02 2e 90 02 02 37 90 02 02 32 90 00 } //00 00 
		$a_00_4 = {5f } //13 00 
	condition:
		any of ($a_*)
 
}