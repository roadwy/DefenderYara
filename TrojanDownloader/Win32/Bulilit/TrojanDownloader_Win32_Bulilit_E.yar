
rule TrojanDownloader_Win32_Bulilit_E{
	meta:
		description = "TrojanDownloader:Win32/Bulilit.E,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {b9 18 00 00 00 33 c0 8d bc 24 ?? 01 00 00 88 9c 24 ?? 01 00 00 f3 ab 66 ab 68 80 00 00 00 aa e8 ?? ?? ff ff 8a d0 b9 18 00 00 00 8a f2 8d bc 24 ?? 01 00 00 8b c2 68 ff 00 00 00 c1 e0 10 66 8b c2 f3 ab 66 ab aa e8 ?? ?? ff ff 8b c8 83 c4 08 c1 e1 06 2b c8 8d 04 88 c1 e0 03 74 } //1
		$a_01_1 = {53 4f 55 4e 25 63 4d 25 63 4e 2e 45 58 45 } //1 SOUN%cM%cN.EXE
		$a_01_2 = {25 73 3f 6d 61 63 3d 25 73 26 76 65 72 3d 25 73 26 50 72 6f 63 65 73 73 4e 75 6d 3d 25 64 } //1 %s?mac=%s&ver=%s&ProcessNum=%d
		$a_01_3 = {43 68 6f 6e 67 54 78 74 } //1 ChongTxt
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}