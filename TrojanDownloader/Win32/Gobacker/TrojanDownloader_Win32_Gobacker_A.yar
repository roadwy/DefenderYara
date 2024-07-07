
rule TrojanDownloader_Win32_Gobacker_A{
	meta:
		description = "TrojanDownloader:Win32/Gobacker.A,SIGNATURE_TYPE_PEHSTR_EXT,07 00 06 00 05 00 00 "
		
	strings :
		$a_01_0 = {66 60 0f 31 69 d0 05 84 08 08 42 8b 44 24 24 f7 e2 } //4
		$a_01_1 = {2f 73 6f 63 6b 73 2f 64 6f 69 74 2e 70 68 70 00 } //1
		$a_01_2 = {25 73 3f 70 6f 72 74 3d 25 64 00 } //1
		$a_01_3 = {5f 4b 49 4c 4c 5f 00 } //1
		$a_01_4 = {5f 55 50 44 41 54 45 5f 00 } //1
	condition:
		((#a_01_0  & 1)*4+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=6
 
}