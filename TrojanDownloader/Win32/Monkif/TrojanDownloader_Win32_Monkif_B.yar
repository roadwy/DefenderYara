
rule TrojanDownloader_Win32_Monkif_B{
	meta:
		description = "TrojanDownloader:Win32/Monkif.B,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_03_0 = {83 f8 ff 74 22 ?? 8d 45 f4 50 6a 10 ?? ?? e8 ?? ?? ?? ?? ?? 8d 45 f4 50 6a 08 90 09 09 00 6a e8 ?? ff 15 } //3
		$a_03_1 = {6a e8 56 ff 15 ?? ?? ?? ?? 83 f8 ff 74 25 53 8d 45 f4 50 6a 10 8d 45 e4 50 56 e8 ?? ?? ff ff 53 8d 45 f4 50 6a 08 } //3
		$a_01_2 = {25 73 25 73 2e 70 68 70 3f 25 73 3d 25 73 00 } //1
		$a_01_3 = {2f 73 6f 64 6f 6d 61 2f 00 } //2
		$a_01_4 = {25 75 7c 25 75 7c 25 75 7c 25 75 } //1 %u|%u|%u|%u
		$a_00_5 = {71 72 6f 63 65 73 73 33 32 66 69 72 73 74 00 00 7a 72 6f 63 65 73 73 33 32 6e 65 78 74 00 } //1
	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*3+(#a_01_2  & 1)*1+(#a_01_3  & 1)*2+(#a_01_4  & 1)*1+(#a_00_5  & 1)*1) >=6
 
}