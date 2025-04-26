
rule TrojanDownloader_Win32_Bredolab_F{
	meta:
		description = "TrojanDownloader:Win32/Bredolab.F,SIGNATURE_TYPE_PEHSTR_EXT,05 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {8a 14 06 8b 5c 24 10 32 14 19 41 88 10 3b 4c 24 14 72 02 } //2
		$a_01_1 = {c6 40 05 e9 8b 45 fc 2b 45 0c 83 e8 0a 89 45 f8 8b 45 0c 8b 4d f8 89 48 06 6a 05 58 } //2
		$a_01_2 = {61 63 74 69 6f 6e 3d 62 6f 74 26 65 6e 74 69 74 79 5f 6c 69 73 74 3d } //1 action=bot&entity_list=
		$a_01_3 = {63 74 69 6f 6e 3d 72 65 70 6f 72 74 26 67 75 69 64 3d 30 26 72 6e 64 3d } //1 ction=report&guid=0&rnd=
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}