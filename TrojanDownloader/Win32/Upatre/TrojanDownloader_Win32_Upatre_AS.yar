
rule TrojanDownloader_Win32_Upatre_AS{
	meta:
		description = "TrojanDownloader:Win32/Upatre.AS,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_01_0 = {83 c4 9c 8b ec e8 00 00 00 00 5b 81 c4 7c ff ff ff 80 e7 f0 6a 06 32 db 53 8d 7d 14 5e 59 33 c0 66 ad 03 c3 ab 49 75 f6 } //1
		$a_01_1 = {b8 04 00 00 00 50 68 00 10 00 00 68 70 15 a7 00 6a 00 ff 93 08 11 00 00 85 c0 } //1
		$a_01_2 = {8b c7 2b 45 00 3d 88 13 00 00 77 73 8b 4d ec 3b c9 75 bc 8b c8 8b 7d b4 8b 07 85 c0 75 b1 8b 75 00 8b 06 46 3d 64 64 72 65 e0 f6 67 e3 a1 46 46 46 ad 2d 73 73 3a 20 75 96 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=2
 
}