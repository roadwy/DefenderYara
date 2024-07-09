
rule TrojanDownloader_Win32_Renos_HK{
	meta:
		description = "TrojanDownloader:Win32/Renos.HK,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {89 45 f0 8b 45 fc 66 ff 0d ?? ?? ?? ?? 8b 34 85 ?? ?? ?? ?? 8d 1c 85 ?? ?? ?? ?? 85 f6 74 ?? 8b 4d f8 8d 3c 8d ?? ?? ?? ?? 8a 06 04 ?? (25 ff 00 00 00|0f b6 c0) 83 c0 ?? 24 ?? e8 ?? ?? ?? ?? 8b cc 8b d6 e8 } //1
		$a_01_1 = {3f 61 73 73 69 67 6e 40 3f 24 62 61 73 69 63 5f 73 74 72 69 6e 67 40 44 55 3f 24 63 68 61 72 5f 74 72 61 69 74 73 40 44 40 73 74 64 40 40 56 3f 24 61 6c 6c 6f 63 61 74 6f 72 40 44 40 32 40 40 73 74 64 40 40 51 41 45 41 41 56 31 32 40 49 44 40 5a } //1 ?assign@?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@QAEAAV12@ID@Z
		$a_01_2 = {47 65 74 50 72 6f 63 41 64 64 72 65 73 73 } //1 GetProcAddress
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}