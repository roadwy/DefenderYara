
rule TrojanDownloader_Win32_Renos_EI{
	meta:
		description = "TrojanDownloader:Win32/Renos.EI,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 07 00 00 "
		
	strings :
		$a_01_0 = {8d 54 24 30 6a 0c 52 68 00 14 2d 00 } //3
		$a_03_1 = {75 0c 43 81 c6 00 02 00 00 83 fb ?? 7c 9e } //3
		$a_03_2 = {eb 0c 3c 2e 75 08 8a 44 24 ?? 84 c0 75 10 4e 85 f6 7f 8a } //2
		$a_01_3 = {75 69 64 3d 25 73 26 6f 73 3d 25 73 } //2 uid=%s&os=%s
		$a_01_4 = {69 64 3d 25 6c 75 26 61 64 76 3d 25 6c 75 26 75 69 64 3d 25 73 } //2 id=%lu&adv=%lu&uid=%s
		$a_01_5 = {5c 5c 2e 5c 50 68 79 73 69 63 61 6c 44 72 69 76 65 25 64 } //1 \\.\PhysicalDrive%d
		$a_01_6 = {77 67 65 74 20 33 2e 30 00 } //1
	condition:
		((#a_01_0  & 1)*3+(#a_03_1  & 1)*3+(#a_03_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=5
 
}