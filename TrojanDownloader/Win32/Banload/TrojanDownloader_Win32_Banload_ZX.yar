
rule TrojanDownloader_Win32_Banload_ZX{
	meta:
		description = "TrojanDownloader:Win32/Banload.ZX,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {89 55 f8 89 45 fc b8 ?? ?? ?? ?? e8 ?? ?? ?? ff 68 ?? ?? ?? ?? 6a 00 e8 ?? ?? ?? ff b2 01 b8 ?? ?? ?? ?? e8 ?? ?? ?? ff 84 c0 75 0a b8 ?? ?? ?? ?? e8 ?? ?? ?? ff ba ?? ?? ?? ?? b8 ?? ?? ?? ?? e8 ?? ?? ?? ff 84 c0 74 ?? 33 d2 } //1
		$a_02_1 = {2f 00 6d 00 61 00 7a 00 64 00 61 00 2e 00 65 00 78 00 65 00 90 0a 50 00 68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 90 0a 30 00 2e 00 65 00 78 00 65 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}