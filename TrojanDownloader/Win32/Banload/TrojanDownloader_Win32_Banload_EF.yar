
rule TrojanDownloader_Win32_Banload_EF{
	meta:
		description = "TrojanDownloader:Win32/Banload.EF,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {55 8b ec 81 c4 f4 f7 ff ff 89 4d f8 89 55 fc 8b 45 fc e8 25 40 fb ff 8b 45 f8 e8 1d 40 fb ff 33 c0 55 68 3f 03 45 00 64 ff 30 64 89 20 8d 85 f7 fb ff ff 8b 55 fc e8 41 80 fb ff 8d 85 f6 f7 ff ff 8b 55 f8 e8 33 80 fb ff 6a 03 6a 00 8d 85 f6 f7 ff ff 50 8d 85 f7 fb ff ff 50 6a 00 6a 00 e8 10 5c fd ff 33 c0 5a 59 59 64 89 10 68 46 03 45 00 8d 45 f8 ba 02 00 00 00 e8 32 3b fb ff c3 e9 0c 35 fb ff eb eb 8b e5 5d c3 } //1
		$a_02_1 = {2e 6a 70 67 00 90 02 ff 2e 6a 70 67 00 90 00 } //1
		$a_02_2 = {00 68 74 74 70 3a 2f 2f 90 02 ff 00 68 74 74 70 3a 2f 2f 90 00 } //1
		$a_02_3 = {2e 73 63 72 00 90 02 ff 2e 73 63 72 00 90 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*1+(#a_02_2  & 1)*1+(#a_02_3  & 1)*1) >=4
 
}