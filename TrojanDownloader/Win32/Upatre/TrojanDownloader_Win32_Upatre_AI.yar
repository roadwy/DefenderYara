
rule TrojanDownloader_Win32_Upatre_AI{
	meta:
		description = "TrojanDownloader:Win32/Upatre.AI,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 05 00 00 "
		
	strings :
		$a_01_0 = {fc ad ab 33 c0 66 ad ab e2 f7 } //2
		$a_03_1 = {5b 83 c3 09 e9 ?? ?? ?? ?? 4c 6f 61 64 4c } //2
		$a_01_2 = {8b 00 fe c8 fe c4 66 3d 4c 5b 0f 84 } //1
		$a_01_3 = {ff d1 2b c2 8b 08 02 cd fe c1 66 81 f9 a8 5a 75 f1 } //1
		$a_01_4 = {63 25 73 25 73 00 25 73 5c 25 73 00 6f 70 65 6e 00 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_03_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=7
 
}