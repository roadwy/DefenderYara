
rule TrojanDownloader_Win32_Bredolab_AA{
	meta:
		description = "TrojanDownloader:Win32/Bredolab.AA,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 02 00 "
		
	strings :
		$a_03_0 = {85 ed 74 5f 83 c5 0e 8b dd a1 90 01 04 e8 90 01 04 a1 90 01 04 50 57 ff 15 90 01 04 83 c4 08 8b e8 a1 90 00 } //01 00 
		$a_03_1 = {57 b9 50 00 00 00 8b d3 a1 90 01 04 e8 90 01 04 8b f8 8b c6 e8 90 00 } //01 00 
		$a_01_2 = {2f 6e 65 77 2f 63 6f 6e 74 72 6f 6c 6c 65 72 2e 70 68 70 00 } //00 00 
	condition:
		any of ($a_*)
 
}