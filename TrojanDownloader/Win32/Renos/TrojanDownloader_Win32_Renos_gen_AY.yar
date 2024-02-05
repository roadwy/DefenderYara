
rule TrojanDownloader_Win32_Renos_gen_AY{
	meta:
		description = "TrojanDownloader:Win32/Renos.gen!AY,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {83 7d f8 34 7d 22 8b 55 f8 52 68 90 01 04 e8 90 01 02 ff ff 83 c4 08 8b 45 fc 50 ff 15 90 01 04 32 c0 e9 90 01 02 00 00 8b 4d f8 51 68 90 01 04 e8 90 01 02 ff ff 83 c4 08 83 7d fc ff 0f 84 90 01 02 00 00 6a 00 6a 00 6a 0b 90 00 } //01 00 
		$a_03_1 = {0f b7 45 e8 c1 f8 08 88 45 e6 0f b7 4d e8 81 e1 ff 00 00 00 88 4d e7 0f b6 55 e7 52 0f b6 45 e6 50 68 90 01 04 e8 90 01 02 ff ff 83 c4 0c 0f b6 4d e6 85 c9 0f 84 90 01 02 00 00 6a 00 8b 55 fc 52 ff 15 90 01 04 0f b7 4d f0 2b c1 83 e8 02 8b 55 10 89 02 90 00 } //01 00 
		$a_01_2 = {73 1c 8b 45 d8 0f b6 08 0f b6 55 e7 33 ca 8b 45 d8 88 08 8b 4d d8 83 c1 01 89 4d d8 eb d1 } //00 00 
	condition:
		any of ($a_*)
 
}