
rule TrojanDownloader_Win32_Tipikit_D{
	meta:
		description = "TrojanDownloader:Win32/Tipikit.D,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {83 ff 00 76 2a 6a 00 e8 90 01 04 6a 90 01 01 8d 45 f0 50 68 90 01 04 e8 90 01 04 0b c0 75 0f e8 90 01 04 24 0f fe c8 30 06 46 4f eb d1 8b 45 08 c9 c2 04 00 90 00 } //1
		$a_03_1 = {89 45 fc 6a 00 6a 00 68 90 01 04 68 90 01 04 6a 00 68 90 01 04 a1 90 01 04 ff d0 ff 75 fc 50 a1 90 01 04 ff d0 ff d0 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}