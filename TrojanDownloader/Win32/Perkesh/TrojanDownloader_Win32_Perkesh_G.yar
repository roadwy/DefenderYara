
rule TrojanDownloader_Win32_Perkesh_G{
	meta:
		description = "TrojanDownloader:Win32/Perkesh.G,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {00 04 32 33 c0 42 f2 ae f7 d1 49 3b d1 72 e6 } //2
		$a_03_1 = {8a c3 b1 03 2c ?? 8b fe f6 e9 00 04 33 } //2
		$a_01_2 = {74 11 68 e0 2e 00 00 ff 15 00 10 40 00 46 3b 75 10 7c d7 } //1
		$a_01_3 = {6a 1e 5e 68 78 e6 00 00 ff 15 00 10 40 00 4e 75 f2 } //1
		$a_01_4 = {3d 3d 22 00 00 7d 1c 33 f6 85 c0 7e 27 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_03_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}