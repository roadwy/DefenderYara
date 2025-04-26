
rule TrojanSpy_Win32_Bugbzla_PQ{
	meta:
		description = "TrojanSpy:Win32/Bugbzla.PQ,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {8b fb 85 f6 75 1b 83 c8 ff e9 a1 00 00 00 66 3b c1 74 01 47 56 e8 bd 2d 00 00 59 8d 34 46 83 c6 02 0f b7 06 6a 3d 59 66 85 c0 75 e2 8d 47 01 } //1
		$a_01_1 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 77 00 77 00 77 00 2e 00 68 00 61 00 69 00 62 00 75 00 67 00 6d 00 6d 00 2e 00 63 00 6f 00 6d 00 2f 00 62 00 61 00 2f 00 79 00 66 00 63 00 74 00 62 00 7a 00 6c 00 61 00 } //1 http://www.haibugmm.com/ba/yfctbzla
	condition:
		((#a_00_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}