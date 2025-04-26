
rule TrojanDownloader_Win32_Chksyn_A{
	meta:
		description = "TrojanDownloader:Win32/Chksyn.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 03 00 07 00 00 "
		
	strings :
		$a_02_0 = {8a 06 6a 10 88 45 fd 8d 45 fc 6a 00 50 e8 ?? ?? 00 00 8b 4d ?? 83 c4 0c 34 ?? ff 45 ?? 46 53 88 01 46 ff d7 } //4
		$a_01_1 = {8b 45 fc 35 11 ca ad de 5b c9 c3 } //4
		$a_03_2 = {56 ff d7 6a 05 8d 74 06 01 68 ?? ?? ?? ?? 56 e8 ?? ?? 00 00 83 c4 0c 85 c0 74 c4 } //4
		$a_01_3 = {5c 5c 2e 5c 70 69 70 65 5c 4e 54 53 76 63 4c 6f 61 64 } //2 \\.\pipe\NTSvcLoad
		$a_01_4 = {69 64 3d 25 78 26 76 65 72 3d 25 64 2e 25 64 26 64 61 74 61 3d 25 73 } //2 id=%x&ver=%d.%d&data=%s
		$a_01_5 = {6e 00 74 00 6d 00 69 00 6e 00 69 00 6c 00 72 00 64 00 } //1 ntminilrd
		$a_01_6 = {6e 00 74 00 72 00 61 00 64 00 6c 00 64 00 72 00 } //1 ntradldr
	condition:
		((#a_02_0  & 1)*4+(#a_01_1  & 1)*4+(#a_03_2  & 1)*4+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=3
 
}