
rule TrojanDownloader_Win32_Zlug_A{
	meta:
		description = "TrojanDownloader:Win32/Zlug.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {6a 01 5b be 90 01 04 89 1d 90 01 04 75 16 6a 63 56 68 85 19 00 00 e8 90 01 04 83 c4 0c 89 1d 90 01 04 56 8d 4d d4 e8 90 01 04 6a 07 89 7d fc 8b 3d 90 01 04 68 90 01 04 56 ff d7 83 c4 0c 85 c0 74 26 6a 06 68 90 01 04 56 ff d7 83 c4 0c 85 c0 90 00 } //1
		$a_02_1 = {8d 8d d0 fe ff ff 51 50 68 90 01 04 e8 90 01 04 83 c4 0c 84 c0 74 34 8d 85 d0 fe ff ff 68 90 01 04 50 ff 15 90 01 04 59 85 c0 59 74 1c 66 a1 90 01 04 50 8d 85 d0 fe ff ff 50 e8 90 01 04 59 3b c6 59 89 45 f0 90 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}