
rule TrojanDownloader_Win32_Bredolab_B{
	meta:
		description = "TrojanDownloader:Win32/Bredolab.B,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 06 00 00 "
		
	strings :
		$a_01_0 = {eb 17 81 e1 ff 00 00 00 8d 5a 01 03 db 33 cb 33 db 8a d8 } //2
		$a_01_1 = {b8 4b 4c 43 cf e8 } //2
		$a_01_2 = {83 c0 17 01 d0 80 38 a1 75 07 c6 05 } //2
		$a_01_3 = {c7 45 fc a1 00 00 00 6a 01 8d 45 fc } //2
		$a_01_4 = {72 bb 5b 8b 46 28 03 45 fc 89 45 f0 8b 55 1c 81 c2 a4 00 00 00 } //2
		$a_01_5 = {45 6e 74 69 74 79 2d 49 6e 66 6f } //1 Entity-Info
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2+(#a_01_5  & 1)*1) >=3
 
}