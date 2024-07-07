
rule TrojanDownloader_Win32_QQHelper_gen_E{
	meta:
		description = "TrojanDownloader:Win32/QQHelper.gen!E,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {55 8b ec 83 ec 20 a1 90 01 03 10 33 c5 89 45 fc a1 90 01 03 10 83 f8 04 75 07 33 c0 a3 90 01 03 10 56 57 33 f6 8b 4d 08 8a 0c 0e 80 f9 61 7c 1f 80 f9 7a 7f 1a 0f be d1 8a 92 90 01 03 10 8b f8 69 ff 01 04 00 00 88 94 37 90 01 03 10 eb 24 80 f9 41 7c 10 80 f9 5a 7f 0b 0f be d1 8a 92 90 01 03 10 eb da 8b d0 69 d2 01 04 00 00 88 8c 32 90 01 03 10 84 c9 74 09 46 81 fe 00 04 00 00 7c a5 68 90 01 03 10 8d 4d e0 e8 90 01 04 a1 90 01 03 10 69 c0 01 04 00 00 ff 05 90 01 03 10 6a 90 01 01 c6 84 30 90 01 05 6a 90 01 01 8d 4d e0 8d b0 90 01 03 10 e8 90 01 04 8b 4d fc 5f 8b c6 33 cd 5e e8 90 01 04 c9 c3 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}