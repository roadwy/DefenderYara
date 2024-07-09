
rule TrojanDownloader_Win32_Banload_AEJ{
	meta:
		description = "TrojanDownloader:Win32/Banload.AEJ,SIGNATURE_TYPE_PEHSTR_EXT,05 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {75 03 8b 75 f4 8b 07 8a 44 18 ff 8b d0 8b 4d f8 8a 4c 31 ff 32 d1 81 e2 ff 00 00 00 8b f2 85 f6 75 08 8b f0 81 e6 ff 00 00 00 8b c7 e8 } //2
		$a_01_1 = {75 03 8b 45 f4 8b 17 0f b7 74 5a fe 8b 55 f8 0f b7 44 42 fe 66 33 f0 0f b7 f6 85 f6 75 07 8b 07 0f b7 74 58 fe 8b c7 e8 } //2
		$a_03_2 = {43 3a 5c 77 69 6e 37 78 65 5c 77 69 6e [0-02] 2e 65 78 65 00 } //1
		$a_80_3 = {30 32 31 38 33 39 34 37 35 36 37 38 33 39 32 32 00 } //0218394756783922  1
		$a_80_4 = {58 46 45 48 09 16 1b } //XFEH	  1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_03_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1) >=4
 
}