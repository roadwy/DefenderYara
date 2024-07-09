
rule TrojanDownloader_Win32_Renos_IE{
	meta:
		description = "TrojanDownloader:Win32/Renos.IE,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_03_0 = {89 45 f4 8d 7d f1 8d 35 ?? ?? ?? ?? b9 03 00 00 00 f3 a4 83 65 fc 00 31 db eb 3d } //2
		$a_01_1 = {77 6e 64 75 74 6c 33 32 2e 64 6c 6c } //1 wndutl32.dll
		$a_01_2 = {63 6f 6e 66 69 67 2e 63 66 67 } //1 config.cfg
		$a_00_3 = {57 00 41 00 4c 00 4c 00 50 00 } //1 WALLP
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_00_3  & 1)*1) >=3
 
}