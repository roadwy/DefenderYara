
rule TrojanDownloader_Win32_Dogkild_N{
	meta:
		description = "TrojanDownloader:Win32/Dogkild.N,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {8d 45 ec 50 ff 15 90 01 04 66 81 7d ec d7 07 0f 86 d0 00 00 00 be 04 01 00 00 8d 85 e8 fe ff ff 56 50 ff 15 90 01 04 8d 85 e8 fe ff ff 68 90 01 04 50 e8 90 01 04 8d 85 e8 fe ff ff 68 90 01 04 50 e8 90 01 04 83 c4 10 66 81 7d ec d8 07 76 16 8d 85 e8 fe ff ff 90 00 } //01 00 
		$a_02_1 = {33 db 53 68 80 00 00 00 6a 03 53 53 68 00 00 00 c0 68 90 01 04 ff 15 90 01 04 83 f8 ff 89 45 fc 74 23 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}