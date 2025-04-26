
rule TrojanDownloader_Win32_Banload_KE{
	meta:
		description = "TrojanDownloader:Win32/Banload.KE,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 06 00 00 "
		
	strings :
		$a_00_0 = {72 65 67 73 76 72 33 32 20 22 00 00 ff ff ff ff 04 00 00 00 22 20 2f 73 00 00 00 00 ff ff ff ff 11 00 00 00 20 2f 73 69 6c 65 6e 74 20 2f 69 6e 73 74 61 6c 6c } //1
		$a_02_1 = {ff ff 6a 00 6a 00 6a 00 6a 00 8d 95 dc fb ff ff b8 ?? ?? ?? ?? e8 ?? ?? ff ff 8b 85 dc fb ff ff e8 ?? ?? ff ff 50 e8 ?? ?? ff ff 8b f8 8d 55 f4 b8 ?? ?? ?? ?? e8 ?? ?? ff ff 8b 5d f4 } //1
		$a_00_2 = {ff ff ff ff 08 00 00 00 5c 6d 6b 70 2e 64 6c 6c 00 } //1
		$a_00_3 = {ff ff ff ff 0e 00 00 00 49 4e 4f 56 41 4e 44 4f 4f 4f 4f 2e 2e 2e 00 } //2
		$a_00_4 = {44 65 6c 65 74 65 55 72 6c 43 61 63 68 65 45 6e 74 72 79 } //10 DeleteUrlCacheEntry
		$a_01_5 = {49 4e 46 45 43 54 } //1 INFECT
	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*2+(#a_00_4  & 1)*10+(#a_01_5  & 1)*1) >=13
 
}