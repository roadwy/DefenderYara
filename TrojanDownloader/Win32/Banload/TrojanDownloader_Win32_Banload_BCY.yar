
rule TrojanDownloader_Win32_Banload_BCY{
	meta:
		description = "TrojanDownloader:Win32/Banload.BCY,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 "
		
	strings :
		$a_01_0 = {33 db 8a 5c 30 ff 33 5d e8 3b fb 7c 0a 81 c3 ff 00 00 00 2b df eb 02 2b df 8d 45 d4 8b d3 } //5
		$a_01_1 = {5c 7a 2e 7a 6c 69 62 } //1 \z.zlib
		$a_01_2 = {5c 61 62 63 64 65 66 2e 65 78 65 } //1 \abcdef.exe
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=7
 
}
rule TrojanDownloader_Win32_Banload_BCY_2{
	meta:
		description = "TrojanDownloader:Win32/Banload.BCY,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 08 00 00 "
		
	strings :
		$a_03_0 = {8d 55 f8 b8 1c 00 00 00 e8 ?? (fd|ff) ff ff 8b 45 f8 8d 55 fc e8 ?? ?? ?? ?? 8b 55 fc b8 ?? ?? ?? ?? e8 ?? ?? ?? ?? b8 ?? ?? ?? ?? b9 ?? ?? ?? ?? 8b 15 } //10
		$a_01_1 = {5c 7a 2e 7a 6c 69 62 00 } //1 穜種楬b
		$a_01_2 = {5c 7a 69 70 2e 7a 00 } //1
		$a_03_3 = {eb f8 68 70 17 00 00 e8 ?? ?? ?? ff a1 ?? ?? ?? ?? e8 ?? ?? ?? ff 84 c0 } //1
		$a_03_4 = {eb f8 68 b8 0b 00 00 e8 ?? ?? ?? ff a1 ?? ?? ?? ?? e8 ?? ?? ?? ff 84 c0 } //1
		$a_03_5 = {eb f8 68 d0 07 00 00 e8 ?? ?? ?? ff a1 ?? ?? ?? ?? e8 ?? ?? ?? ff 84 c0 } //1
		$a_03_6 = {eb f8 68 58 1b 00 00 e8 ?? ?? ?? ff a1 ?? ?? ?? ?? e8 ?? ?? ?? ff 84 c0 } //1
		$a_03_7 = {eb f8 68 40 1f 00 00 e8 ?? ?? ?? ff a1 ?? ?? ?? ?? e8 ?? ?? ?? ff 84 c0 } //1
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1+(#a_03_4  & 1)*1+(#a_03_5  & 1)*1+(#a_03_6  & 1)*1+(#a_03_7  & 1)*1) >=11
 
}