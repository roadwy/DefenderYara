
rule TrojanDownloader_Win32_Bredolab_AA{
	meta:
		description = "TrojanDownloader:Win32/Bredolab.AA,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_03_0 = {85 ed 74 5f 83 c5 0e 8b dd a1 ?? ?? ?? ?? e8 ?? ?? ?? ?? a1 ?? ?? ?? ?? 50 57 ff 15 ?? ?? ?? ?? 83 c4 08 8b e8 a1 } //2
		$a_03_1 = {57 b9 50 00 00 00 8b d3 a1 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b f8 8b c6 e8 } //1
		$a_01_2 = {2f 6e 65 77 2f 63 6f 6e 74 72 6f 6c 6c 65 72 2e 70 68 70 00 } //1
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=2
 
}