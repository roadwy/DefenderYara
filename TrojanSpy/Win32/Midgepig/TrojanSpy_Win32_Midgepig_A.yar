
rule TrojanSpy_Win32_Midgepig_A{
	meta:
		description = "TrojanSpy:Win32/Midgepig.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {ff d7 ff d3 8b c8 b8 d3 4d 62 10 2b 4c 24 14 f7 e1 c1 ea 06 83 fa 3c 73 05 e8 ?? ?? ?? ?? 68 60 ea 00 00 ff d6 eb cc } //1
		$a_01_1 = {8b 46 30 0f b7 08 66 85 c9 74 30 66 83 f9 6a 75 07 66 83 78 02 70 74 0e 0f b7 48 02 83 c0 02 66 85 c9 75 e7 } //1
		$a_01_2 = {69 6d 67 5c 00 00 00 00 25 73 25 64 2d 25 30 2e 32 64 2d 25 30 2e 32 64 5f 25 30 2e 32 64 2d 25 30 2e 32 64 2d 25 30 2e 32 64 2e 6a 70 67 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}