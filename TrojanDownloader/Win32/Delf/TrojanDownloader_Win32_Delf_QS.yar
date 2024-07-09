
rule TrojanDownloader_Win32_Delf_QS{
	meta:
		description = "TrojanDownloader:Win32/Delf.QS,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {7e 2b be 01 00 00 00 8d 45 f0 8b d7 52 8b 55 fc 8a 54 32 ff 59 2a d1 f6 d2 } //1
		$a_03_1 = {8b 4d f8 8b 55 fc e8 ?? ?? ff ff 84 c0 74 20 33 d2 8b 45 f8 e8 ?? ?? ff ff b8 88 13 00 00 e8 } //1
		$a_01_2 = {79 00 c5 92 7a 00 d9 a6 72 00 e9 b8 68 00 fb bc 63 00 e0 a8 7b 00 e9 b5 74 00 b7 c8 7e 00 ff c1 4f 00 ff c7 5d 00 db cb 65 00 fd c3 64 00 f9 ca 76 00 e9 d1 71 00 fd d6 7b 00 00 00 00 00 5c bc 86 00 6e ca } //1
		$a_01_3 = {d9 8b 00 ff ce 85 00 f9 d2 86 00 ed c1 92 00 f2 cc 9a 00 fa d9 94 00 e9 e2 9b 00 fe e6 9a 00 c6 c0 aa 00 c3 d8 ad 00 db c3 b4 00 e8 c5 a7 00 f3 c8 aa 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}