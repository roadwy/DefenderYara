
rule TrojanSpy_Win32_Nivdort_DH{
	meta:
		description = "TrojanSpy:Win32/Nivdort.DH,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {0f b6 50 03 88 51 fe 0f b6 50 02 88 51 ff 8b 10 c1 ea 08 88 11 0f b6 10 88 51 01 83 c0 04 83 c1 04 83 ee 01 75 da } //2
		$a_03_1 = {79 05 49 83 c9 e0 41 0f b6 84 0c ?? ?? 00 00 99 bd 1a 00 00 00 f7 fd 80 c2 61 88 94 34 ?? ?? 00 00 46 3b f7 75 } //2
		$a_03_2 = {77 61 74 63 68 5f 64 6f 67 5f 6e 61 6d 65 2e 65 78 65 [0-10] 2f 69 6e 64 65 78 2e 70 68 70 3f 64 61 74 61 3d [0-10] 4c 4f 43 4b [0-10] 77 62 } //2
		$a_01_3 = {41 44 52 49 41 4e 43 4f 50 49 4c 55 4c 4d 49 4e 55 4e 45 53 49 46 4c 4f 52 49 4e 53 41 4c 41 4d } //1 ADRIANCOPILULMINUNESIFLORINSALAM
	condition:
		((#a_01_0  & 1)*2+(#a_03_1  & 1)*2+(#a_03_2  & 1)*2+(#a_01_3  & 1)*1) >=4
 
}