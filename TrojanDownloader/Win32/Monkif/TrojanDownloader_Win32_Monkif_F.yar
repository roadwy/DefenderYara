
rule TrojanDownloader_Win32_Monkif_F{
	meta:
		description = "TrojanDownloader:Win32/Monkif.F,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 07 00 00 "
		
	strings :
		$a_03_0 = {bc 00 00 00 75 ?? c7 05 ?? ?? ?? ?? 78 1c 00 00 eb } //2
		$a_03_1 = {00 02 00 00 74 de 81 3d ?? ?? ?? ?? 01 02 00 00 74 d2 } //2
		$a_01_2 = {c6 45 f4 4c c6 45 f5 6f c6 45 f6 63 c6 45 f7 61 c6 45 f8 6c c6 45 f9 5c c6 45 fa 55 c6 45 fb 49 c6 45 fc 45 c6 45 fd 49 } //2
		$a_01_3 = {ff 45 fc 8b 45 fc 6b c0 60 8d 34 18 33 ff 39 3e 75 cd } //1
		$a_00_4 = {25 73 25 73 2e 70 68 70 3f 25 73 3d 25 73 00 } //1
		$a_01_5 = {25 75 7c 25 75 7c 25 75 7c 25 75 7c 25 75 7c 25 75 00 } //1 甥╼籵甥╼籵甥╼u
		$a_01_6 = {2f 62 61 62 79 6c 6f 6e 2f 00 } //1 戯扡汹湯/
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*1+(#a_00_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=5
 
}