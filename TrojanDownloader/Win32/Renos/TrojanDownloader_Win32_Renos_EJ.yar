
rule TrojanDownloader_Win32_Renos_EJ{
	meta:
		description = "TrojanDownloader:Win32/Renos.EJ,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 "
		
	strings :
		$a_03_0 = {8a 1e 2b ca 80 f3 ?? 66 89 0d ?? ?? ?? ?? 66 49 66 89 0d ?? ?? ?? ?? 88 1c 37 } //4
		$a_03_1 = {0f 95 c0 a2 ?? ?? ?? 00 33 c0 66 39 1d ?? ?? ?? 00 0f 95 c0 a2 ?? ?? ?? 00 eb 17 cc eb } //2
		$a_01_2 = {33 c0 50 0f 01 4c 24 fe 58 c3 } //2
		$a_01_3 = {80 0d d8 bb 40 00 ff 3d 00 00 00 d0 77 07 3d 00 00 00 80 73 06 ff d6 2b c5 eb dc } //4
	condition:
		((#a_03_0  & 1)*4+(#a_03_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*4) >=8
 
}