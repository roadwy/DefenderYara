
rule TrojanDownloader_Win32_Monkif_G{
	meta:
		description = "TrojanDownloader:Win32/Monkif.G,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {c6 45 f4 4c c6 45 f5 6f c6 45 f6 63 c6 45 f7 61 c6 45 f8 6c c6 45 f9 5c c6 45 fa 55 c6 45 fb 49 c6 45 fc 45 c6 45 fd 49 } //4
		$a_01_1 = {8d 0c 10 8a 4c 0d d0 3a 4c 15 d0 75 06 42 83 fa 20 72 ed 83 fa 20 75 6e } //1
		$a_01_2 = {58 6a 0f 50 cb } //1
		$a_01_3 = {58 b9 0f 00 00 00 51 50 cb } //1
		$a_01_4 = {75 e1 ff 45 fc 8b 45 fc 6b c0 60 8d 34 18 33 ff 39 3e 75 cd } //1
	condition:
		((#a_01_0  & 1)*4+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}