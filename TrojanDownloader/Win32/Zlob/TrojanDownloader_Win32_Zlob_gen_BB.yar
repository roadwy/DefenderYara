
rule TrojanDownloader_Win32_Zlob_gen_BB{
	meta:
		description = "TrojanDownloader:Win32/Zlob.gen!BB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {8b f7 74 10 2b cf 32 44 24 18 88 06 46 8a 04 31 84 c0 75 f2 } //2
		$a_01_1 = {8b c8 74 10 2b f0 32 54 24 0c 88 11 41 8a 14 0e 84 d2 75 f2 } //2
		$a_01_2 = {c6 45 e7 01 83 65 fc 00 52 51 53 b8 68 58 4d 56 bb 00 00 00 00 b9 0a 00 00 00 ba 58 56 00 00 ed 81 fb 68 58 4d 56 0f 94 45 e7 } //1
		$a_03_3 = {51 50 c6 85 ?? fe ff ff 47 c6 85 ?? fe ff ff 45 c6 85 ?? fe ff ff 54 88 9d ?? fe ff ff ff 15 } //2
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_03_3  & 1)*2) >=3
 
}