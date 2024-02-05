
rule TrojanDownloader_Win32_Nymaim_H{
	meta:
		description = "TrojanDownloader:Win32/Nymaim.H,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {0f b6 f3 33 d2 8b c6 f7 f1 a3 90 01 04 32 c0 eb 29 8b 3d 90 1b 00 0f b6 f3 ff 15 90 01 04 0f b6 4d ff 8d 8c 31 31 ff ff ff 33 c1 2b f8 8a c3 32 45 ff 89 3d 90 1b 00 8b 4d f8 8b fb 88 01 c1 ef 10 90 00 } //01 00 
		$a_03_1 = {ff 75 08 c3 90 09 0c 00 8d 15 90 01 04 52 68 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}