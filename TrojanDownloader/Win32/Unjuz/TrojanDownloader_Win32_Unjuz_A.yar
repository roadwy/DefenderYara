
rule TrojanDownloader_Win32_Unjuz_A{
	meta:
		description = "TrojanDownloader:Win32/Unjuz.A,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0a 00 06 00 00 "
		
	strings :
		$a_01_0 = {75 6e 7a 6a 73 2e 63 6f 6d 2f 74 65 73 74 5f 63 6f 6e 66 69 67 2f } //1 unzjs.com/test_config/
		$a_01_1 = {67 2e 75 75 65 2e 63 6e 2f 75 75 2f } //1 g.uue.cn/uu/
		$a_01_2 = {25 2e 32 64 2d 25 2e 32 64 2d 25 2e 32 64 2d 25 73 3d 25 2e 34 64 2d 25 2e 32 64 2d 25 2e 32 64 } //1 %.2d-%.2d-%.2d-%s=%.4d-%.2d-%.2d
		$a_01_3 = {89 45 b0 50 8d 45 f4 64 a3 00 00 00 00 89 8d 84 fb ff ff 8d 85 ac fb ff ff 50 6a 00 6a 00 6a 1a 6a 00 ff 15 } //3
		$a_01_4 = {81 7d c4 2d 01 00 00 74 16 81 7d c4 2e 01 00 00 74 0d 81 7d c4 2f 01 00 00 0f 85 86 02 00 00 6a 00 8d 55 b8 52 6a 16 8b 4d cc } //3
		$a_01_5 = {8b 4d cc 8b 11 8b 4d cc 8b 42 4c ff d0 8b 4d cc 89 8d 88 fb ff ff 8b 95 88 fb ff ff 89 95 8c fb ff ff 83 bd 8c fb ff ff 00 } //3
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*3+(#a_01_4  & 1)*3+(#a_01_5  & 1)*3) >=10
 
}