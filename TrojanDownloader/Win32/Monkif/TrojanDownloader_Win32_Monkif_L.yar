
rule TrojanDownloader_Win32_Monkif_L{
	meta:
		description = "TrojanDownloader:Win32/Monkif.L,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 05 00 00 "
		
	strings :
		$a_01_0 = {25 73 25 73 2e 70 68 70 3f 25 73 25 63 25 73 } //2 %s%s.php?%s%c%s
		$a_03_1 = {76 10 8b 44 24 04 03 c1 80 30 90 01 01 41 3b 4c 24 08 72 f0 90 00 } //2
		$a_03_2 = {03 00 00 74 de 81 3d 90 01 02 00 10 01 03 00 00 74 d2 90 00 } //2
		$a_01_3 = {63 c6 45 f5 74 c6 45 f6 65 c6 45 f7 64 c6 45 f8 5a c6 45 f9 74 c6 45 fa 61 } //2
		$a_01_4 = {3d fe fb 0f 00 7c dd 5e 81 c4 00 02 00 00 c3 } //2
	condition:
		((#a_01_0  & 1)*2+(#a_03_1  & 1)*2+(#a_03_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2) >=8
 
}