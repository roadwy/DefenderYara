
rule TrojanDownloader_Win32_Delf_AY{
	meta:
		description = "TrojanDownloader:Win32/Delf.AY,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {55 8b ec 81 c4 f4 f7 ff ff 89 55 f8 89 45 fc 8b 45 fc e8 05 bb ff ff 8b 45 f8 e8 fd ba ff ff 33 c0 55 68 a3 7e 40 00 64 ff 30 64 89 20 8d 85 f7 fb ff ff 8b 55 fc e8 b9 d7 ff ff 8d 85 f6 f7 ff ff 8b 55 f8 e8 ab d7 ff ff 6a 00 6a 00 8d 85 f6 f7 ff ff 50 8d 85 f7 fb ff ff 50 6a 00 6a ?? e8 e0 c7 ff ff 33 c0 5a 59 59 64 89 10 68 aa 7e 40 00 8d 45 f8 ba 02 00 00 00 e8 76 b7 ff ff c3 e9 74 b1 ff ff eb eb 8b e5 5d c3 } //1
		$a_02_1 = {00 00 00 00 b0 7e 40 00 55 8b ec 83 c4 f0 b8 d8 7e 40 00 e8 ec c4 ff ff 33 d2 b8 ?? 7f 40 00 e8 d0 fe ff ff ba ?? 7f 40 00 b8 ?? ?? 40 00 e8 21 fe ff ff 84 c0 74 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}