
rule TrojanDownloader_Win32_Prockets_A{
	meta:
		description = "TrojanDownloader:Win32/Prockets.A,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {83 ec 64 56 57 68 90 01 04 6a 64 ff 15 90 01 04 a1 90 01 04 3d 90 01 04 7d 1f 33 f6 85 c0 7e 2e 8b 3d 90 01 04 68 90 01 04 ff d7 a1 90 01 04 46 3b f0 7c ef eb 15 8b 3d 90 01 04 be 90 01 04 68 90 01 04 ff d7 4e 75 f6 68 90 01 04 e8 90 01 04 a1 90 01 04 83 c4 04 83 c0 20 8d 4c 24 08 68 90 01 04 50 68 90 01 04 68 90 01 04 51 ff 15 90 01 04 8d 54 24 1c 6a 0a 52 68 90 01 04 e8 90 01 04 83 c4 20 5f 5e 83 c4 64 c3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}