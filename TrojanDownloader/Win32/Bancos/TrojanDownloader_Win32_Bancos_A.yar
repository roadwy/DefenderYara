
rule TrojanDownloader_Win32_Bancos_A{
	meta:
		description = "TrojanDownloader:Win32/Bancos.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {66 bb 01 00 e9 ?? 00 00 00 8d 45 ?? 8b 55 ?? 8a 54 3a ff 88 50 01 c6 00 01 8d 55 ?? 8d 45 ?? e8 ?? ?? ff ff 8d 45 ?? 0f b7 d3 8b 4d ?? 8a 14 11 88 50 01 c6 00 01 8d 55 ?? 8d 45 ?? b1 02 e8 ?? ?? ff ff } //1
		$a_03_1 = {ba 05 00 00 00 e8 ?? ?? ff ff 8b 45 ?? e8 ?? ?? ff ff 50 6a 00 e8 ?? ?? ff ff 8d 55 ?? b8 ?? ?? ?? 00 e8 ?? ?? ff ff 8b 55 } //1
		$a_00_2 = {55 72 6c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } //1 UrlDownloadToFileA
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}