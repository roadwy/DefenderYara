
rule TrojanDownloader_Win32_Oderoor_gen_A{
	meta:
		description = "TrojanDownloader:Win32/Oderoor.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 06 00 00 "
		
	strings :
		$a_00_0 = {25 73 3f 72 75 6e 3d 31 00 } //10
		$a_01_1 = {25 73 3f 64 3d 25 64 00 25 73 3f 69 3d 31 00 } //1
		$a_01_2 = {2f 63 25 75 2e 65 78 65 00 } //1
		$a_01_3 = {25 73 25 30 38 78 2e 74 6d 70 00 } //1
		$a_03_4 = {ab ab 6a 10 8d 45 90 01 01 50 53 ff 15 90 01 04 85 c0 7d 04 33 c0 eb 90 01 01 ff 75 90 01 01 8d 85 90 01 02 ff ff ff 75 90 01 01 68 90 00 } //3
		$a_03_5 = {83 c0 0f eb 01 40 80 38 20 74 fa 8a 08 89 5c 24 90 01 01 3a cb 74 90 01 01 8b f0 8a c1 2c 90 01 01 3c 90 01 01 77 90 00 } //3
	condition:
		((#a_00_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_03_4  & 1)*3+(#a_03_5  & 1)*3) >=13
 
}