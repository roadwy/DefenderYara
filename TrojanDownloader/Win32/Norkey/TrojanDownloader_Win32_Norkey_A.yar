
rule TrojanDownloader_Win32_Norkey_A{
	meta:
		description = "TrojanDownloader:Win32/Norkey.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {8a 51 01 41 84 d2 75 f8 a1 90 01 04 66 8b 15 90 01 04 89 01 a0 90 01 04 66 89 51 04 88 41 06 85 f6 0f 84 90 01 04 6a 00 6a 00 6a 00 6a 00 8d 4c 24 90 01 01 51 56 ff 54 24 2c 90 00 } //01 00 
		$a_03_1 = {8a 47 01 47 84 c0 75 f8 6a 00 b9 06 00 00 00 be 90 01 04 6a 00 f3 a5 6a 02 6a 00 6a 00 68 00 00 00 40 8d 84 24 c8 00 00 00 50 a4 ff 54 24 34 89 44 24 14 c7 44 24 18 28 23 00 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}