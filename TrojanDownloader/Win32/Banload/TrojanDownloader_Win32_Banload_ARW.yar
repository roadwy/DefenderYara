
rule TrojanDownloader_Win32_Banload_ARW{
	meta:
		description = "TrojanDownloader:Win32/Banload.ARW,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {25 52 41 4e 44 4f 4d 25 00 } //1
		$a_03_1 = {7e 2f bf 01 00 00 00 8b c3 34 01 84 c0 74 1b 8d 45 f0 8b 55 fc 0f b6 54 3a ff e8 ?? ?? ?? ff 8b 55 f0 8d 45 f8 e8 ?? ?? ?? ff 80 f3 01 47 } //1
		$a_03_2 = {75 05 83 fb 03 7e d9 8d 4d 90 09 20 00 8d 55 ?? b8 ?? ?? ?? ?? e8 ?? ?? ff ff 8b 45 ?? 8b 55 ?? e8 ?? ?? ff ff 88 45 ?? 43 80 7d ?? 00 } //1
		$a_03_3 = {8b 85 e0 ef ff ff e8 ?? ?? ?? ff 50 e8 ?? ?? ff ff 8b f0 85 f6 0f 84 cd 00 00 00 6a 00 68 00 01 00 84 6a 00 6a 00 8b 45 fc e8 ?? ?? ?? ff 50 56 e8 90 09 0a 00 b8 ?? ?? ?? ?? e8 ?? ?? ?? ff } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1) >=3
 
}