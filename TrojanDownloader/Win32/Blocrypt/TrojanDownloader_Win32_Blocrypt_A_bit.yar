
rule TrojanDownloader_Win32_Blocrypt_A_bit{
	meta:
		description = "TrojanDownloader:Win32/Blocrypt.A!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {0f b7 05 50 ec 47 00 8b 1d 90 01 04 33 c6 33 c1 8a 90 01 05 41 81 f9 90 01 04 88 14 18 7c 90 00 } //01 00 
		$a_03_1 = {99 59 f7 f9 85 d2 74 17 66 81 3d 90 01 06 75 3b a1 90 01 04 03 c3 80 30 90 01 01 eb 90 00 } //01 00 
		$a_03_2 = {ff d5 8b c8 8b 44 24 90 01 01 33 d2 f7 f1 2c 90 01 01 30 06 43 81 fb 90 01 04 7d 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}